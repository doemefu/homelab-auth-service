package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.LoginThrottleProperties;
import ch.furchert.homelab.auth.config.LoginThrottleProperties.Limits;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Failed-attempt throttle with temporary locks (#104). In memory only: one replica, and a restart
 * clears every counter, the known-good networks and the client fingerprints.
 * <ul>
 *   <li>Form login ({@link LoginThrottleFilter}): one key per submitted username (lower-cased, trimmed)
 *   and one per client IP (IPv6 aggregated to its /64). A (username, network) pair that logged in
 *   successfully within {@code known-good-ttl} passes the username lock, and the IP lock unless the
 *   username is locked as well; it is still bounded by the number of attempts in flight.</li>
 *   <li>Client authentication ({@link ThrottlingClientSecretAuthenticationProvider}): one key per
 *   (client IP, client_id). A secret that already authenticated this client since the last restart
 *   passes the lock, so once a client has authenticated, nobody else can lock it out. The client IP comes
 *   from a header that callers inside the cluster can forge, so a second, IP-independent key per client_id
 *   counts failures from all sources: past its threshold the client is in strict mode, where every source
 *   gets a single failed attempt. Strict mode never rejects a source without failures, so it cannot lock a
 *   working client out.</li>
 * </ul>
 * Only failures count. {@code max-failures} failures inside {@code window} lock the key for
 * {@code lock-duration}; attempts during a lock are rejected before any credential check and are not
 * counted, so a lock always ends. A success resets the count but never lifts an active lock. For
 * attempts without an exemption, failures plus attempts in flight never exceed {@code max-failures}.
 * Keys are salted SHA-256 digests, so neither huge inputs nor plaintext usernames are kept and table
 * positions cannot be predicted. When a table is full of active entries, a new key is throttled on one of
 * {@value #OVERFLOW_SHARDS} overflow keys chosen by its salted hash; a success never resets an overflow
 * key. Log lines never contain
 * a username, an IP or a secret; client locks name the (registered) client id.
 * {@code users.status} is never touched and no authorization is revoked.
 */
@Component
@Slf4j
public class LoginThrottle {

    public enum Outcome { SUCCESS, FAILURE, NONE }

    /** Request attribute carrying the form-login {@link Outcome} from the event listener to the filter. */
    public static final String OUTCOME_ATTRIBUTE = LoginThrottle.class.getName() + ".OUTCOME";

    static final int MAX_CLIENT_ENTRIES = 10_000;
    static final int MAX_KNOWN_GOOD_USERS = 10_000;
    static final int KNOWN_GOOD_NETWORKS_PER_USER = 8;
    static final int FINGERPRINTS_PER_CLIENT = 4;
    static final int OVERFLOW_SHARDS = 256;
    private static final int EVICTION_SAMPLE = 16;
    private static final long FULL_SCAN_INTERVAL_MILLIS = 10_000;
    private static final long WARNING_INTERVAL_MILLIS = 60_000;

    enum Kind {
        USER("username"), IP("client IP"), CLIENT("client"), CLIENT_ID("client id (all sources)");

        final String label;

        Kind(String label) {
            this.label = label;
        }
    }

    /** How far an attempt is exempt: not at all, from locks only (in-flight bound kept), or completely. */
    private enum Exemption { NONE, LOCK, FULL }

    /** Salted SHA-256 digest of {@code kind:value}; fixed size whatever the input. */
    record Key(long a, long b, long c, long d) {
    }

    record Counter(int failures, int inFlight, long windowStart, long lockedUntil) {
        boolean lockedAt(long now) {
            return lockedUntil > now;
        }

        boolean idleAt(long now) {
            return failures == 0 && inFlight == 0 && !lockedAt(now);
        }
    }

    public record Admission(boolean admitted, Ticket ticket, Duration retryAfter) {
    }

    /** {@code maxFailures} 0 = the kind's configured threshold. */
    private record Slot(Kind kind, Key key, boolean overflow, int maxFailures) {
    }

    private record Reservation(boolean admitted, Slot slot, boolean lockedAtAcquire, Duration retryAfter) {
    }

    /** Handle of one admitted attempt; only its first {@link #complete} counts. */
    public static final class Ticket {
        private final List<Slot> slots;
        private final Key userKey;
        private final Key networkKey;
        private final String clientId;
        private final byte[] fingerprint;
        private final boolean fingerprintExempt;
        private final AtomicBoolean completed = new AtomicBoolean();

        private Ticket(List<Slot> slots, Key userKey, Key networkKey, String clientId, byte[] fingerprint,
                       boolean fingerprintExempt) {
            this.slots = slots;
            this.userKey = userKey;
            this.networkKey = networkKey;
            this.clientId = clientId;
            this.fingerprint = fingerprint;
            this.fingerprintExempt = fingerprintExempt;
        }
    }

    private final LoginThrottleProperties properties;
    private final Clock clock;
    private final byte[] keySalt = new byte[32];
    private final byte[] fingerprintKey = new byte[32];
    private final Map<Kind, ConcurrentHashMap<Key, Counter>> counters = new EnumMap<>(Kind.class);
    private final Map<Kind, Key[]> overflowKeys = new EnumMap<>(Kind.class);
    private final Set<Key> allOverflowKeys = new HashSet<>();
    /** username key → (network key → last success); a few networks per username. */
    private final ConcurrentHashMap<Key, Map<Key, Long>> knownGood = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<byte[]>> clientFingerprints = new ConcurrentHashMap<>();
    private final Map<Kind, AtomicLong> lastFullScan = new EnumMap<>(Kind.class);
    private final Map<Kind, AtomicLong> rejectedLocked = new EnumMap<>(Kind.class);
    private final Map<Kind, AtomicLong> rejectedInFlight = new EnumMap<>(Kind.class);
    private final Map<Kind, AtomicLong> overflowed = new EnumMap<>(Kind.class);
    private final AtomicBoolean missingContextWarned = new AtomicBoolean();
    private final AtomicBoolean missingIpWarned = new AtomicBoolean();
    private final AtomicLong fullScans = new AtomicLong();
    private volatile int evictionSample = EVICTION_SAMPLE;

    @Autowired
    public LoginThrottle(LoginThrottleProperties properties) {
        this(properties, Clock.systemUTC());
    }

    LoginThrottle(LoginThrottleProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        SecureRandom random = new SecureRandom();
        random.nextBytes(keySalt);          // per process: table positions cannot be precomputed
        random.nextBytes(fingerprintKey);   // per process: fingerprints are only compared in this process
        for (Kind kind : Kind.values()) {
            counters.put(kind, new ConcurrentHashMap<>());
            Key[] shards = new Key[OVERFLOW_SHARDS];
            for (int i = 0; i < OVERFLOW_SHARDS; i++) {
                shards[i] = key("overflow", kind.name() + ":" + i);
                allOverflowKeys.add(shards[i]);
            }
            overflowKeys.put(kind, shards);
            lastFullScan.put(kind, new AtomicLong(Long.MIN_VALUE / 2));
            rejectedLocked.put(kind, new AtomicLong());
            rejectedInFlight.put(kind, new AtomicLong());
            overflowed.put(kind, new AtomicLong());
        }
        if (properties.isEnabled()) {
            log.info("Login throttle enabled: username {}, client IP {}, client {} (max failures / window / lock)",
                    describe(properties.getUser()), describe(properties.getIp()), describe(properties.getClient()));
        } else {
            log.warn("Login throttle DISABLED (app.login-throttle.enabled=false): no brute-force protection "
                    + "on POST /login and client authentication");
        }
    }

    private static String describe(Limits l) {
        return l.getMaxFailures() + "/" + l.getWindow() + "/" + l.getLockDuration();
    }

    public boolean isEnabled() {
        return properties.isEnabled();
    }

    // ---- form login -------------------------------------------------------------------------------

    public Admission acquireLogin(String username, String clientIp) {
        if (!isEnabled()) {
            return new Admission(true, null, Duration.ZERO);
        }
        long now = clock.millis();
        String user = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        String network = network(clientIp);
        if (network == null) {
            warnOnce(missingIpWarned, "no client IP; only the username key applies");
        }
        Key userKey = key("user", user);
        Key networkKey = network == null ? null : key("ip", network);
        boolean knownNetwork = networkKey != null && isKnownGood(userKey, networkKey, now);

        Reservation u = reserve(Kind.USER, userKey, now, knownNetwork ? Exemption.LOCK : Exemption.NONE);
        if (!u.admitted()) {
            return new Admission(false, null, u.retryAfter());
        }
        List<Slot> slots = new ArrayList<>(2);
        slots.add(u.slot());
        if (networkKey != null) {
            Exemption ipExemption = knownNetwork && !u.lockedAtAcquire() ? Exemption.LOCK : Exemption.NONE;
            Reservation i = reserve(Kind.IP, networkKey, now, ipExemption);
            if (!i.admitted()) {
                release(slots, now);
                return new Admission(false, null, i.retryAfter());
            }
            slots.add(i.slot());
        }
        return new Admission(true, new Ticket(slots, userKey, networkKey, null, null, false), Duration.ZERO);
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        if (event.getAuthentication() instanceof UsernamePasswordAuthenticationToken) {
            markOutcome(Outcome.SUCCESS);
        }
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        if (event.getAuthentication() instanceof UsernamePasswordAuthenticationToken) {
            markOutcome(outcomeOf(event));
        }
    }

    /** Wrong credentials and account-status failures count; infrastructure errors (e.g. DB down) do not. */
    static Outcome outcomeOf(AbstractAuthenticationFailureEvent event) {
        boolean counts = event instanceof AuthenticationFailureBadCredentialsEvent
                || event instanceof AuthenticationFailureDisabledEvent
                || event instanceof AuthenticationFailureLockedEvent
                || event instanceof AuthenticationFailureExpiredEvent
                || event instanceof AuthenticationFailureCredentialsExpiredEvent;
        return counts ? Outcome.FAILURE : Outcome.NONE;
    }

    private void markOutcome(Outcome outcome) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            attributes.setAttribute(OUTCOME_ATTRIBUTE, outcome, RequestAttributes.SCOPE_REQUEST);
        } else {
            warnOnce(missingContextWarned, "no request context for a form-login event; the attempt is not counted");
        }
    }

    private static void warnOnce(AtomicBoolean flag, String what) {
        if (flag.compareAndSet(false, true)) {
            log.warn("Login throttle: {} (logged once)", what);
        }
    }

    // ---- client authentication ----------------------------------------------------------------------

    public Admission acquireClient(String clientId, String clientIp, String presentedSecret) {
        if (!isEnabled()) {
            return new Admission(true, null, Duration.ZERO);
        }
        long now = clock.millis();
        String network = network(clientIp);
        if (network == null) {
            warnOnce(missingIpWarned, "no client IP; client keys fall back to one key per client id");
        }
        byte[] fingerprint = presentedSecret == null ? null : fingerprint(clientId, presentedSecret);
        boolean known = fingerprint != null && isKnownFingerprint(clientId, fingerprint);
        if (known) {
            // A known secret is a correct secret: no guessing is possible, so no bound and nothing to count.
            Reservation r = reserve(Kind.CLIENT, clientKey(network, clientId), now, Exemption.FULL, 0);
            return new Admission(true, new Ticket(List.of(r.slot()), null, null, clientId, fingerprint, true),
                    Duration.ZERO);
        }
        Key clientIdKey = key("client-id", clientId);
        boolean strict = isLocked(Kind.CLIENT_ID, clientIdKey, now);
        Reservation r = reserve(Kind.CLIENT, clientKey(network, clientId), now, Exemption.NONE, strict ? 1 : 0);
        if (!r.admitted()) {
            return new Admission(false, null, r.retryAfter());
        }
        // Counts failures from every source; never rejects (strict mode only tightens the per-source key).
        Reservation all = reserve(Kind.CLIENT_ID, clientIdKey, now, Exemption.FULL, 0);
        return new Admission(true, new Ticket(List.of(r.slot(), all.slot()), null, null, clientId, fingerprint,
                false), Duration.ZERO);
    }

    private Key clientKey(String network, String clientId) {
        return key("client", (network == null ? "-" : network) + "|" + clientId);
    }

    private boolean isLocked(Kind kind, Key key, long now) {
        Counter c = normalize(counters.get(kind).get(key), limits(kind), now);
        return c != null && c.lockedAt(now);
    }

    // ---- shared bookkeeping -------------------------------------------------------------------------

    public void complete(Ticket ticket, Outcome outcome) {
        if (ticket == null || !ticket.completed.compareAndSet(false, true)) {
            return;
        }
        long now = clock.millis();
        for (Slot slot : ticket.slots) {
            int lockedAfter = completeSlot(slot, outcome, now);
            if (lockedAfter > 0) {
                logLock(slot.kind(), ticket.clientId, lockedAfter);
            }
        }
        if (outcome == Outcome.SUCCESS) {
            if (ticket.userKey != null && ticket.networkKey != null) {
                rememberKnownGood(ticket.userKey, ticket.networkKey, now);
            }
            if (ticket.clientId != null && ticket.fingerprint != null) {
                rememberFingerprint(ticket.clientId, ticket.fingerprint);
            }
        } else if (outcome == Outcome.FAILURE && ticket.fingerprintExempt) {
            forgetFingerprint(ticket.clientId, ticket.fingerprint);   // the secret was rotated
        }
    }

    /** Drops expired entries and logs how many attempts were rejected since the last run (counts only). */
    @Scheduled(fixedDelay = 60_000)
    public void purgeExpired() {
        long now = clock.millis();
        for (Kind kind : Kind.values()) {
            purge(kind, now);
        }
        long ttl = properties.getKnownGoodTtl().toMillis();
        for (Key user : knownGood.keySet()) {
            knownGood.computeIfPresent(user, (k, networks) -> {
                Map<Key, Long> kept = new LinkedHashMap<>();
                networks.forEach((n, t) -> {
                    if (now - t < ttl) {
                        kept.put(n, t);
                    }
                });
                return kept.isEmpty() ? null : Map.copyOf(kept);
            });
        }
        reportRejections();
    }

    private void reportRejections() {
        StringBuilder sb = new StringBuilder();
        long total = 0;
        for (Kind kind : Kind.values()) {
            long locked = rejectedLocked.get(kind).getAndSet(0);
            long inFlight = rejectedInFlight.get(kind).getAndSet(0);
            long over = overflowed.get(kind).getAndSet(0);
            if (locked + inFlight + over > 0) {
                sb.append(sb.isEmpty() ? "" : "; ").append(kind.label).append(": ").append(locked)
                        .append(" locked, ").append(inFlight).append(" in-flight bound, ")
                        .append(over).append(" via overflow key");
                total += locked + inFlight;
            }
        }
        if (!sb.isEmpty()) {
            log.warn("Login throttle: rejected {} attempts since the last report ({})", total, sb);
        }
    }

    /** Forgets every counter, known-good network and fingerprint (tests; a pod restart does the same). */
    public void clear() {
        counters.values().forEach(Map::clear);
        knownGood.clear();
        clientFingerprints.clear();
    }

    int trackedEntries() {
        return counters.values().stream().mapToInt(Map::size).sum() + knownGood.size();
    }

    Counter peek(String kind, String value) {
        return counters.get(Kind.valueOf(kind.toUpperCase(Locale.ROOT).replace('-', '_'))).get(key(kind, value));
    }

    /** Tests: 0 skips the sample, so every eviction goes through the full scan. */
    void setEvictionSample(int sample) {
        this.evictionSample = sample;
    }

    long fullScans() {
        return fullScans.get();
    }

    /** Overflow shard of a value, as {@link #reserve} picks it. */
    int overflowShard(String kind, String value) {
        return shard(key(kind, value));
    }

    Counter peekOverflow(String kind, int shard) {
        Kind k = Kind.valueOf(kind.toUpperCase(Locale.ROOT));
        return counters.get(k).get(overflowKeys.get(k)[shard]);
    }

    private static int shard(Key key) {
        return (int) Long.remainderUnsigned(key.a(), OVERFLOW_SHARDS);
    }

    private Limits limits(Kind kind) {
        return switch (kind) {
            case USER -> properties.getUser();
            case IP -> properties.getIp();
            case CLIENT -> properties.getClient();
            case CLIENT_ID -> properties.getClientId();
        };
    }

    private int capacity(Kind kind) {
        return kind == Kind.CLIENT || kind == Kind.CLIENT_ID ? MAX_CLIENT_ENTRIES : properties.getMaxEntries();
    }

    /** Lock expired → fresh window; window expired without a lock → count restarts. In-flight is kept. */
    private static Counter normalize(Counter c, Limits limits, long now) {
        if (c == null) {
            return null;
        }
        if (c.lockedUntil() != 0 && c.lockedUntil() <= now) {
            return new Counter(0, c.inFlight(), now, 0);
        }
        if (c.lockedUntil() == 0 && now - c.windowStart() >= limits.getWindow().toMillis()) {
            return new Counter(0, c.inFlight(), now, 0);
        }
        return c;
    }

    private Reservation reserve(Kind kind, Key key, long now, Exemption exemption) {
        return reserve(kind, key, now, exemption, 0);
    }

    /** @param maxOverride a stricter threshold for this attempt (strict mode), 0 = the kind's own */
    private Reservation reserve(Kind kind, Key key, long now, Exemption exemption, int maxOverride) {
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        Key effective = key;
        boolean overflow = false;
        if (!map.containsKey(key) && map.size() >= capacity(kind) && !makeRoom(kind, now)) {
            // Full of active entries: the new key is throttled on its overflow shard (salted hash), so
            // locking one shard never blocks the other new keys.
            effective = overflowKeys.get(kind)[shard(key)];
            overflow = true;
            overflowed.get(kind).incrementAndGet();
        }
        Limits limits = limits(kind);
        Key slotKey = effective;
        boolean overflowSlot = overflow;
        Reservation[] out = new Reservation[1];
        map.compute(slotKey, (k, old) -> {
            Counter c = normalize(old, limits, now);
            if (c == null) {
                c = new Counter(0, 0, now, 0);
            }
            int max = maxOverride > 0 ? Math.min(maxOverride, limits.getMaxFailures()) : limits.getMaxFailures();
            boolean locked = c.lockedAt(now);
            boolean full = c.failures() + c.inFlight() >= max;
            boolean reject = switch (exemption) {
                case NONE -> locked || full;
                case LOCK -> c.inFlight() >= max;
                case FULL -> false;
            };
            if (reject) {
                (locked && exemption == Exemption.NONE ? rejectedLocked : rejectedInFlight).get(kind).incrementAndGet();
                Duration retry = locked ? Duration.ofMillis(c.lockedUntil() - now) : Duration.ofSeconds(1);
                out[0] = new Reservation(false, null, locked, retry);
                return c.idleAt(now) ? null : c;
            }
            out[0] = new Reservation(true, new Slot(kind, slotKey, overflowSlot, maxOverride), locked, Duration.ZERO);
            return new Counter(c.failures(), c.inFlight() + 1, c.windowStart(), c.lockedUntil());
        });
        return out[0];
    }

    private void release(List<Slot> slots, long now) {
        slots.forEach(slot -> completeSlot(slot, Outcome.NONE, now));
    }

    /** @return the failure count that just locked the key, or 0 */
    private int completeSlot(Slot slot, Outcome outcome, long now) {
        Limits limits = limits(slot.kind());
        int[] lockedAfter = {0};
        counters.get(slot.kind()).computeIfPresent(slot.key(), (k, old) -> {
            Counter c = normalize(old, limits, now);
            int inFlight = Math.max(0, c.inFlight() - 1);
            int failures = c.failures();
            long windowStart = c.windowStart();
            long lockedUntil = c.lockedUntil();
            int max = slot.maxFailures() > 0
                    ? Math.min(slot.maxFailures(), limits.getMaxFailures()) : limits.getMaxFailures();
            if (outcome == Outcome.FAILURE) {
                failures++;
                if (failures >= max && lockedUntil <= now) {
                    lockedUntil = now + limits.getLockDuration().toMillis();
                    lockedAfter[0] = failures;
                }
            } else if (outcome == Outcome.SUCCESS && slot.kind() != Kind.IP && slot.kind() != Kind.CLIENT_ID
                    && !slot.overflow()) {
                // A success proves the credential: reset the count, but an active lock stays, so a
                // legitimate login never hands an attacker a fresh budget. An overflow key is shared, so
                // one user's success proves nothing about the others and never resets it.
                failures = 0;
                windowStart = now;
            }
            Counter next = new Counter(failures, inFlight, windowStart, lockedUntil);
            return next.idleAt(now) ? null : next;
        });
        return lockedAfter[0];
    }

    private void logLock(Kind kind, String clientId, int failures) {
        long seconds = limits(kind).getLockDuration().toSeconds();
        if (kind == Kind.CLIENT) {
            // Failures are only counted for registered clients, so this is never attacker-chosen text.
            log.warn("Login throttle: client '{}' locked for {} s after {} failed attempts",
                    sanitize(clientId), seconds, failures);
        } else if (kind == Kind.CLIENT_ID) {
            log.warn("Login throttle: client '{}' in strict mode for {} s after {} failed attempts from all sources "
                    + "(one failed attempt per source)", sanitize(clientId), seconds, failures);
        } else {
            log.warn("Login throttle: {} locked for {} s after {} failed attempts", kind.label, seconds, failures);
        }
    }

    private static String sanitize(String value) {
        String s = value == null ? "" : value.replaceAll("[^A-Za-z0-9._:-]", "?");
        return s.length() <= 64 ? s : s.substring(0, 64);
    }

    private void purge(Kind kind, long now) {
        Limits limits = limits(kind);
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        for (Key key : map.keySet()) {
            map.computeIfPresent(key, (k, c) -> {
                Counter n = normalize(c, limits, now);
                return n.idleAt(now) ? null : n;
            });
        }
    }

    private static boolean evictable(Counter c, long now) {
        return !c.lockedAt(now) && c.inFlight() == 0;
    }

    /**
     * Bounded work: evict the entry with the fewest failures out of a small sample; if the sample holds no
     * evictable entry, at most every 10 s per table, purge and scan the whole table. Locked or in-flight
     * entries are never evicted.
     */
    private boolean makeRoom(Kind kind, long now) {
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        Key victim = pickVictim(map, now, evictionSample);
        if (victim == null) {
            AtomicLong last = lastFullScan.get(kind);
            long previous = last.get();
            if (now - previous >= FULL_SCAN_INTERVAL_MILLIS && last.compareAndSet(previous, now)) {
                fullScans.incrementAndGet();
                purge(kind, now);
                if (map.size() < capacity(kind)) {
                    return true;
                }
                victim = pickVictim(map, now, Integer.MAX_VALUE);
            }
        }
        if (victim != null) {
            map.computeIfPresent(victim, (k, c) -> evictable(c, now) ? null : c);
        }
        return map.size() < capacity(kind);
    }

    private Key pickVictim(Map<Key, Counter> map, long now, int sample) {
        if (sample <= 0) {
            return null;
        }
        Key victim = null;
        int fewest = Integer.MAX_VALUE;
        int seen = 0;
        for (Map.Entry<Key, Counter> e : map.entrySet()) {
            Counter c = e.getValue();
            if (!allOverflowKeys.contains(e.getKey()) && evictable(c, now) && c.failures() < fewest) {
                victim = e.getKey();
                fewest = c.failures();
            }
            if (++seen >= sample) {
                break;
            }
        }
        return victim;
    }

    private boolean isKnownGood(Key user, Key network, long now) {
        Map<Key, Long> networks = knownGood.get(user);
        Long since = networks == null ? null : networks.get(network);
        return since != null && now - since < properties.getKnownGoodTtl().toMillis();
    }

    /**
     * Per username, the {@value #KNOWN_GOOD_NETWORKS_PER_USER} most recent networks; one account's logins
     * can therefore never push another username's networks out. Only a new username can evict another
     * username's list, and only when {@value #MAX_KNOWN_GOOD_USERS} usernames have successful logins.
     */
    private void rememberKnownGood(Key user, Key network, long now) {
        if (!knownGood.containsKey(user) && knownGood.size() >= MAX_KNOWN_GOOD_USERS) {
            knownGood.entrySet().stream()
                    .min((a, b) -> Long.compare(newest(a.getValue()), newest(b.getValue())))
                    .ifPresent(oldest -> knownGood.remove(oldest.getKey(), oldest.getValue()));
        }
        knownGood.compute(user, (k, networks) -> {
            LinkedHashMap<Key, Long> next = new LinkedHashMap<>();
            next.put(network, now);
            if (networks != null) {
                networks.entrySet().stream()
                        .filter(e -> !e.getKey().equals(network))
                        .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                        .limit(KNOWN_GOOD_NETWORKS_PER_USER - 1L)
                        .forEach(e -> next.put(e.getKey(), e.getValue()));
            }
            return Map.copyOf(next);
        });
    }

    private static long newest(Map<Key, Long> networks) {
        return networks.values().stream().mapToLong(Long::longValue).max().orElse(Long.MIN_VALUE);
    }

    private byte[] fingerprint(String clientId, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(fingerprintKey, "HmacSHA256"));
            return mac.doFinal((clientId + "\n" + secret).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private boolean isKnownFingerprint(String clientId, byte[] fingerprint) {
        List<byte[]> known = clientFingerprints.get(clientId);
        return known != null && known.stream().anyMatch(f -> MessageDigest.isEqual(f, fingerprint));
    }

    private void rememberFingerprint(String clientId, byte[] fingerprint) {
        clientFingerprints.compute(clientId, (id, known) -> {
            List<byte[]> next = new ArrayList<>(FINGERPRINTS_PER_CLIENT);
            next.add(fingerprint);
            if (known != null) {
                known.stream().filter(f -> !MessageDigest.isEqual(f, fingerprint))
                        .limit(FINGERPRINTS_PER_CLIENT - 1L).forEach(next::add);
            }
            return List.copyOf(next);
        });
    }

    private void forgetFingerprint(String clientId, byte[] fingerprint) {
        clientFingerprints.computeIfPresent(clientId, (id, known) -> {
            List<byte[]> next = known.stream().filter(f -> !MessageDigest.isEqual(f, fingerprint)).toList();
            return next.isEmpty() ? null : next;
        });
    }

    Key key(String kind, String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(keySalt);
            byte[] d = digest.digest((kind + ":" + value).getBytes(StandardCharsets.UTF_8));
            ByteBuffer b = ByteBuffer.wrap(d);
            return new Key(b.getLong(), b.getLong(), b.getLong(), b.getLong());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** IPv4 as is; IPv6 aggregated to its /64 (one subscriber); null when there is no IP. */
    static String network(String ip) {
        if (ip == null || ip.isBlank()) {
            return null;
        }
        if (ip.indexOf(':') < 0) {
            return ip;
        }
        try {
            byte[] bytes = InetAddress.ofLiteral(ip).getAddress();
            if (bytes.length != 16) {
                return ip;
            }
            Arrays.fill(bytes, 8, 16, (byte) 0);
            return InetAddress.getByAddress(bytes).getHostAddress() + "/64";
        } catch (IllegalArgumentException | java.net.UnknownHostException e) {
            return ip;
        }
    }
}
