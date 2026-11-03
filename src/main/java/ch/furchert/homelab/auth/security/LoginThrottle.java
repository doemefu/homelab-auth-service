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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Failed-attempt throttle with temporary locks (#104). In memory only: one replica, and a restart
 * clears every counter.
 * <ul>
 *   <li>Form login ({@link LoginThrottleFilter}): one key per submitted username (lower-cased, trimmed)
 *   and one per client IP (IPv6 aggregated to its /64). A (username, network) pair that logged in
 *   successfully within {@code known-good-ttl} is exempt from the username lock, and from the IP lock
 *   unless the username is locked as well.</li>
 *   <li>Client authentication ({@link ThrottlingClientSecretAuthenticationProvider}): one key per
 *   (client IP, client_id). A secret that already authenticated this client in this process passes
 *   the lock, so nobody can lock a working client out.</li>
 * </ul>
 * Only failures count. {@code max-failures} failures inside {@code window} lock the key for
 * {@code lock-duration}; attempts during a lock are rejected before any credential check and are not
 * counted, so a lock always ends. Username and IP keys also bound attempts in flight. Keys are SHA-256
 * digests, so neither huge inputs nor plaintext usernames are kept. Log lines never contain a username,
 * an IP or a secret; client locks name the (registered) client id.
 * {@code users.status} is never touched and no authorization is revoked.
 */
@Component
@Slf4j
public class LoginThrottle {

    public enum Outcome { SUCCESS, FAILURE, NONE }

    /** Request attribute carrying the form-login {@link Outcome} from the event listener to the filter. */
    public static final String OUTCOME_ATTRIBUTE = LoginThrottle.class.getName() + ".OUTCOME";

    static final int MAX_CLIENT_ENTRIES = 10_000;
    static final int MAX_KNOWN_GOOD_ENTRIES = 10_000;
    static final int FINGERPRINTS_PER_CLIENT = 4;
    private static final int EVICTION_SAMPLE = 16;
    private static final long FULL_PURGE_INTERVAL_MILLIS = 10_000;
    private static final long FULL_WARNING_INTERVAL_MILLIS = 60_000;

    enum Kind {
        USER("username"), IP("client IP"), CLIENT("client");

        final String label;

        Kind(String label) {
            this.label = label;
        }
    }

    /** SHA-256 digest of {@code kind:value}; fixed size whatever the input. */
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

    private record Slot(Kind kind, Key key) {
    }

    private record Reservation(boolean admitted, Slot slot, boolean lockedAtAcquire, Duration retryAfter) {
        static Reservation untracked() {
            return new Reservation(true, null, false, Duration.ZERO);
        }
    }

    /** Handle of one admitted attempt; complete it exactly once with {@link #complete}. */
    public static final class Ticket {
        private final List<Slot> slots;
        private final Key knownGoodKey;
        private final String clientId;
        private final byte[] fingerprint;

        private Ticket(List<Slot> slots, Key knownGoodKey, String clientId, byte[] fingerprint) {
            this.slots = slots;
            this.knownGoodKey = knownGoodKey;
            this.clientId = clientId;
            this.fingerprint = fingerprint;
        }
    }

    private final LoginThrottleProperties properties;
    private final Clock clock;
    private final Map<Kind, ConcurrentHashMap<Key, Counter>> counters = new EnumMap<>(Kind.class);
    private final ConcurrentHashMap<Key, Long> knownGood = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<byte[]>> clientFingerprints = new ConcurrentHashMap<>();
    private final byte[] fingerprintKey = new byte[32];
    private final AtomicLong lastFullPurge = new AtomicLong(Long.MIN_VALUE / 2);
    private final AtomicLong lastFullWarning = new AtomicLong(Long.MIN_VALUE / 2);

    @Autowired
    public LoginThrottle(LoginThrottleProperties properties) {
        this(properties, Clock.systemUTC());
    }

    LoginThrottle(LoginThrottleProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        for (Kind kind : Kind.values()) {
            counters.put(kind, new ConcurrentHashMap<>());
        }
        // Per-process key: fingerprints are only ever compared inside this process.
        new SecureRandom().nextBytes(fingerprintKey);
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
        Key knownGoodKey = network == null ? null : key("good", user + "|" + network);
        boolean exempt = knownGoodKey != null && isKnownGood(knownGoodKey, now);

        Reservation u = reserve(Kind.USER, key("user", user), now, true, exempt);
        if (!u.admitted()) {
            return new Admission(false, null, u.retryAfter());
        }
        List<Slot> slots = new ArrayList<>(2);
        if (u.slot() != null) {
            slots.add(u.slot());
        }
        if (network != null) {
            Reservation i = reserve(Kind.IP, key("ip", network), now, true, exempt && !u.lockedAtAcquire());
            if (!i.admitted()) {
                release(slots, now);
                return new Admission(false, null, i.retryAfter());
            }
            if (i.slot() != null) {
                slots.add(i.slot());
            }
        }
        return new Admission(true, new Ticket(slots, knownGoodKey, null, null), Duration.ZERO);
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

    private static void markOutcome(Outcome outcome) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            attributes.setAttribute(OUTCOME_ATTRIBUTE, outcome, RequestAttributes.SCOPE_REQUEST);
        }
    }

    // ---- client authentication ----------------------------------------------------------------------

    public Admission acquireClient(String clientId, String clientIp, String presentedSecret) {
        if (!isEnabled()) {
            return new Admission(true, null, Duration.ZERO);
        }
        long now = clock.millis();
        String network = network(clientIp);
        byte[] fingerprint = presentedSecret == null ? null : fingerprint(clientId, presentedSecret);
        boolean exempt = fingerprint != null && isKnownFingerprint(clientId, fingerprint);
        Reservation r = reserve(Kind.CLIENT, key("client", (network == null ? "-" : network) + "|" + clientId),
                now, false, exempt);
        if (!r.admitted()) {
            return new Admission(false, null, r.retryAfter());
        }
        List<Slot> slots = r.slot() == null ? List.of() : List.of(r.slot());
        return new Admission(true, new Ticket(slots, null, clientId, fingerprint), Duration.ZERO);
    }

    // ---- shared bookkeeping -------------------------------------------------------------------------

    public void complete(Ticket ticket, Outcome outcome) {
        if (ticket == null) {
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
            if (ticket.knownGoodKey != null) {
                rememberKnownGood(ticket.knownGoodKey, now);
            }
            if (ticket.clientId != null && ticket.fingerprint != null) {
                rememberFingerprint(ticket.clientId, ticket.fingerprint);
            }
        }
    }

    /** Drops expired counters and known-good pairs. */
    @Scheduled(fixedDelay = 60_000)
    public void purgeExpired() {
        long now = clock.millis();
        for (Kind kind : Kind.values()) {
            purge(kind, now);
        }
        long ttl = properties.getKnownGoodTtl().toMillis();
        knownGood.entrySet().removeIf(e -> now - e.getValue() >= ttl);
    }

    /** Forgets every counter, known-good pair and fingerprint (tests; a pod restart does the same). */
    public void clear() {
        counters.values().forEach(Map::clear);
        knownGood.clear();
        clientFingerprints.clear();
    }

    int trackedEntries() {
        return counters.values().stream().mapToInt(Map::size).sum() + knownGood.size();
    }

    Counter peek(String kind, String value) {
        return counters.get(Kind.valueOf(kind.toUpperCase(Locale.ROOT))).get(key(kind, value));
    }

    private Limits limits(Kind kind) {
        return switch (kind) {
            case USER -> properties.getUser();
            case IP -> properties.getIp();
            case CLIENT -> properties.getClient();
        };
    }

    private int capacity(Kind kind) {
        return kind == Kind.CLIENT ? MAX_CLIENT_ENTRIES : properties.getMaxEntries();
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

    private Reservation reserve(Kind kind, Key key, long now, boolean hardBound, boolean exempt) {
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        if (!map.containsKey(key) && map.size() >= capacity(kind) && !makeRoom(kind, now)) {
            if (lastFullWarning.get() + FULL_WARNING_INTERVAL_MILLIS <= now) {
                lastFullWarning.set(now);
                log.warn("Login throttle: {} table full of active entries; new keys are not tracked", kind.label);
            }
            return Reservation.untracked();
        }
        Limits limits = limits(kind);
        Reservation[] out = new Reservation[1];
        map.compute(key, (k, old) -> {
            Counter c = normalize(old, limits, now);
            if (c == null) {
                c = new Counter(0, 0, now, 0);
            }
            boolean locked = c.lockedAt(now);
            int pending = c.failures() + c.inFlight();
            boolean full = hardBound ? pending >= limits.getMaxFailures()
                    : c.failures() > 0 && pending >= limits.getMaxFailures();
            if (!exempt && (locked || full)) {
                Duration retry = locked ? Duration.ofMillis(c.lockedUntil() - now) : Duration.ofSeconds(1);
                out[0] = new Reservation(false, null, true, retry);
                return c.idleAt(now) ? null : c;
            }
            out[0] = new Reservation(true, new Slot(kind, key), locked, Duration.ZERO);
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
            if (outcome == Outcome.FAILURE) {
                failures++;
                if (failures >= limits.getMaxFailures() && lockedUntil <= now) {
                    lockedUntil = now + limits.getLockDuration().toMillis();
                    lockedAfter[0] = failures;
                }
            } else if (outcome == Outcome.SUCCESS && slot.kind() != Kind.IP) {
                // A success proves the credential: reset the username/client key, keep in-flight bookkeeping.
                failures = 0;
                windowStart = now;
                lockedUntil = 0;
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

    /** Bounded work: an occasional purge, then evict one unlocked, idle entry out of a small sample. */
    private boolean makeRoom(Kind kind, long now) {
        ConcurrentHashMap<Key, Counter> map = counters.get(kind);
        long last = lastFullPurge.get();
        if (now - last >= FULL_PURGE_INTERVAL_MILLIS && lastFullPurge.compareAndSet(last, now)) {
            purge(kind, now);
        }
        if (map.size() < capacity(kind)) {
            return true;
        }
        Key victim = null;
        int fewest = Integer.MAX_VALUE;
        int seen = 0;
        for (Map.Entry<Key, Counter> e : map.entrySet()) {
            Counter c = e.getValue();
            if (!c.lockedAt(now) && c.inFlight() == 0 && c.failures() < fewest) {
                victim = e.getKey();
                fewest = c.failures();
            }
            if (++seen >= EVICTION_SAMPLE) {
                break;
            }
        }
        if (victim != null) {
            map.computeIfPresent(victim, (k, c) -> !c.lockedAt(now) && c.inFlight() == 0 ? null : c);
        }
        return map.size() < capacity(kind);
    }

    private boolean isKnownGood(Key key, long now) {
        Long since = knownGood.get(key);
        return since != null && now - since < properties.getKnownGoodTtl().toMillis();
    }

    private void rememberKnownGood(Key key, long now) {
        if (!knownGood.containsKey(key) && knownGood.size() >= MAX_KNOWN_GOOD_ENTRIES) {
            long ttl = properties.getKnownGoodTtl().toMillis();
            knownGood.entrySet().removeIf(e -> now - e.getValue() >= ttl);
            if (knownGood.size() >= MAX_KNOWN_GOOD_ENTRIES) {
                knownGood.entrySet().stream().min(Map.Entry.comparingByValue())
                        .ifPresent(oldest -> knownGood.remove(oldest.getKey(), oldest.getValue()));
            }
        }
        knownGood.put(key, now);
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

    static Key key(String kind, String value) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest((kind + ":" + value).getBytes(StandardCharsets.UTF_8));
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
