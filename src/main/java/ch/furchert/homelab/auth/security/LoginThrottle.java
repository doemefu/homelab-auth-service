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
 *   counts failures from all sources: past its threshold the client is in strict mode, where each tracked
 *   source gets one attempt at a time and is rejected after one failure until its window ends, without a
 *   lock (overflow keys keep their own bound). A known secret is always admitted. Strict mode does not stop a caller who forges
 *   the header (#133).</li>
 * </ul>
 * Only failures count. {@code max-failures} failures inside {@code window} lock the key for
 * {@code lock-duration}; attempts during a lock are rejected before any credential check and are not
 * counted, so a lock always ends. A success resets the count but never lifts an active lock. For
 * attempts without an exemption, failures plus attempts in flight never exceed {@code max-failures}.
 * Keys are salted SHA-256 digests, so neither huge inputs nor plaintext usernames are kept and table
 * positions cannot be predicted. When a table is full of active entries, a new key is counted on one of
 * {@value #OVERFLOW_SHARDS} overflow keys chosen by its secret-salted hash. An overflow key never locks: it
 * bounds failures within a short window ({@code 60 s}) and attempts in flight, and rejects fast with a
 * Retry-After of at most 60 s; a success never resets it. Nothing ever sleeps on a request thread. Log
 * lines never contain
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
    static final Duration OVERFLOW_WINDOW = Duration.ofSeconds(60);
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

    private record Slot(Kind kind, Key key, boolean overflow) {
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
    private final Map<Kind, AtomicLong> rejectedStrict = new EnumMap<>(Kind.class);
    private final Map<Kind, AtomicLong> rejectedOverflow = new EnumMap<>(Kind.class);
    private final Map<Kind, AtomicLong> overflowed = new EnumMap<>(Kind.class);
    private final AtomicBoolean missingContextWarned = new AtomicBoolean();
    private final AtomicBoolean missingIpWarned = new AtomicBoolean();
    private final AtomicLong fullScans = new AtomicLong();
    private volatile int evictionSample = EVICTION_SAMPLE;
    private volatile int clientCapacity = MAX_CLIENT_ENTRIES;

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
            rejectedStrict.put(kind, new AtomicLong());
            rejectedOverflow.put(kind, new AtomicLong());
            overflowed.put(kind, new AtomicLong());
        }
        if (properties.isEnabled()) {
            log.info("Login throttle enabled: username {}, client IP {}, client {}, client id strict mode {} "
                            + "(max failures / window / lock)", describe(properties.getUser()),
                    describe(properties.getIp()), describe(properties.getClient()), describe(properties.getClientId()));
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
            Reservation r = reserve(Kind.CLIENT, clientKey(network, clientId), now, Exemption.FULL, false);
            return new Admission(true, new Ticket(List.of(r.slot()), null, null, clientId, fingerprint, true),
                    Duration.ZERO);
        }
        Key clientIdKey = key("client-id", clientId);
        boolean strict = isLocked(Kind.CLIENT_ID, clientIdKey, now);
        Reservation r = reserve(Kind.CLIENT, clientKey(network, clientId), now, Exemption.NONE, strict);
        if (!r.admitted()) {
            return new Admission(false, null, r.retryAfter());
        }
        // Counts failures from every source; never rejects (strict mode only tightens the per-source key).
        Reservation all = reserve(Kind.CLIENT_ID, clientIdKey, now, Exemption.FULL, false);
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
            long strict = rejectedStrict.get(kind).getAndSet(0);
            long overflowRejects = rejectedOverflow.get(kind).getAndSet(0);
            long over = overflowed.get(kind).getAndSet(0);
            if (locked + inFlight + strict + overflowRejects + over > 0) {
                sb.append(sb.isEmpty() ? "" : "; ").append(kind.label).append(": ").append(locked)
                        .append(" locked, ").append(inFlight).append(" in-flight bound, ").append(strict)
                        .append(" strict mode, ").append(overflowRejects).append(" overflow bound (")
                        .append(over).append(" attempts on overflow keys)");
                total += locked + inFlight + strict + overflowRejects;
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

    /** Tests: shrink the client tables. */
    void setClientCapacity(int capacity) {
        this.clientCapacity = capacity;
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
        return kind == Kind.CLIENT || kind == Kind.CLIENT_ID ? clientCapacity : properties.getMaxEntries();
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
        return reserve(kind, key, now, exemption, false);
    }

    /** @param strict client strict mode: one attempt at a time, and rejected after one failure in the window */
    private Reservation reserve(Kind kind, Key key, long now, Exemption exemption, boolean strict) {
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        Key effective = key;
        boolean overflow = false;
        if (!map.containsKey(key) && map.size() >= capacity(kind) && !makeRoom(kind, now)) {
            // Full of active entries: the new key is counted on its overflow shard (salted hash).
            effective = overflowKeys.get(kind)[shard(key)];
            overflow = true;
            overflowed.get(kind).incrementAndGet();
        }
        boolean overflowSlot = overflow;
        Limits limits = overflowSlot ? overflowLimits(kind) : limits(kind);
        Key slotKey = effective;
        Reservation[] out = new Reservation[1];
        map.compute(slotKey, (k, old) -> {
            Counter c = normalize(old, limits, now);
            if (c == null) {
                c = new Counter(0, 0, now, 0);
            }
            int max = limits.getMaxFailures();
            // Overflow keys are shared, so they never lock: a short window and the in-flight bound reject fast.
            boolean locked = !overflowSlot && c.lockedAt(now);
            // Strict mode only tightens tracked per-source keys: an overflow shard is shared by bystanders.
            boolean full = c.failures() + c.inFlight() >= (strict && !overflowSlot ? 1 : max);
            boolean reject = switch (exemption) {
                case NONE -> locked || full;
                case LOCK -> c.inFlight() >= max;
                case FULL -> false;
            };
            if (reject) {
                boolean lockedReject = locked && exemption == Exemption.NONE;
                (lockedReject ? rejectedLocked : overflowSlot ? rejectedOverflow
                        : strict ? rejectedStrict : rejectedInFlight).get(kind).incrementAndGet();
                Duration retry = lockedReject ? Duration.ofMillis(c.lockedUntil() - now)
                        : c.failures() > 0
                        ? Duration.ofMillis(Math.max(1000, c.windowStart() + limits.getWindow().toMillis() - now))
                        : Duration.ofSeconds(1);
                out[0] = new Reservation(false, null, locked, retry);
                return c.idleAt(now) ? null : c;
            }
            out[0] = new Reservation(true, new Slot(kind, slotKey, overflowSlot), locked, Duration.ZERO);
            return new Counter(c.failures(), c.inFlight() + 1, c.windowStart(), overflowSlot ? 0 : c.lockedUntil());
        });
        return out[0];
    }

    /** Same failure threshold as the kind, but a 60 s window and no lock (see reserve/completeSlot). */
    private Limits overflowLimits(Kind kind) {
        return new Limits(limits(kind).getMaxFailures(), OVERFLOW_WINDOW, OVERFLOW_WINDOW);
    }

    private void release(List<Slot> slots, long now) {
        slots.forEach(slot -> completeSlot(slot, Outcome.NONE, now));
    }

    /** @return the failure count that just locked the key, or 0 */
    private int completeSlot(Slot slot, Outcome outcome, long now) {
        Limits limits = slot.overflow() ? overflowLimits(slot.kind()) : limits(slot.kind());
        int[] lockedAfter = {0};
        counters.get(slot.kind()).computeIfPresent(slot.key(), (k, old) -> {
            Counter c = normalize(old, limits, now);
            int inFlight = Math.max(0, c.inFlight() - 1);
            int failures = c.failures();
            long windowStart = c.windowStart();
            long lockedUntil = c.lockedUntil();
            if (outcome == Outcome.FAILURE) {
                failures++;
                if (!slot.overflow() && failures >= limits.getMaxFailures() && lockedUntil <= now) {
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
                    + "(one attempt at a time per source, rejected after one failure)", sanitize(clientId), seconds, failures);
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
        Limits overflow = overflowLimits(kind);
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        for (Key key : map.keySet()) {
            map.computeIfPresent(key, (k, c) -> {
                Counter n = normalize(c, allOverflowKeys.contains(k) ? overflow : limits, now);
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
