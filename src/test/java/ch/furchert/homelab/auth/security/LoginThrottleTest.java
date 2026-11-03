package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.LoginThrottleProperties;
import ch.furchert.homelab.auth.security.LoginThrottle.Admission;
import ch.furchert.homelab.auth.security.LoginThrottle.Outcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class LoginThrottleTest {

    /** Mutable clock for window and lock expiry. */
    static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-11-03T00:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private LoginThrottleProperties props;
    private TestClock clock;
    private LoginThrottle throttle;

    @BeforeEach
    void setUp() {
        props = new LoginThrottleProperties();
        props.setUser(new LoginThrottleProperties.Limits(3, Duration.ofMinutes(15), Duration.ofMinutes(5)));
        props.setIp(new LoginThrottleProperties.Limits(5, Duration.ofMinutes(15), Duration.ofMinutes(15)));
        props.setClient(new LoginThrottleProperties.Limits(3, Duration.ofMinutes(5), Duration.ofMinutes(5)));
        clock = new TestClock();
        throttle = new LoginThrottle(props, clock);
    }

    private boolean login(String user, String ip, Outcome outcome) {
        Admission a = throttle.acquireLogin(user, ip);
        if (a.admitted()) {
            throttle.complete(a.ticket(), outcome);
        }
        return a.admitted();
    }

    private boolean client(String clientId, String ip, String secret, Outcome outcome) {
        Admission a = throttle.acquireClient(clientId, ip, secret);
        if (a.admitted()) {
            throttle.complete(a.ticket(), outcome);
        }
        return a.admitted();
    }

    @Test
    void usernameLocksAfterMaxFailuresAndNotBefore() {
        assertThat(login("owner", "203.0.113.1", Outcome.FAILURE)).isTrue();
        assertThat(login("owner", "203.0.113.2", Outcome.FAILURE)).isTrue();
        assertThat(throttle.acquireLogin("owner", "203.0.113.3").admitted()).isTrue();   // 2 failures: still open
        throttle.clear();
        for (int i = 0; i < 3; i++) {
            assertThat(login("owner", "203.0.113." + i, Outcome.FAILURE)).isTrue();
        }
        Admission locked = throttle.acquireLogin("owner", "198.51.100.7");   // any IP: the username is locked
        assertThat(locked.admitted()).isFalse();
        assertThat(locked.retryAfter()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void usernameMatchingIgnoresCaseAndSurroundingSpace() {
        for (int i = 0; i < 3; i++) {
            login(" Owner ", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", "198.51.100.7").admitted()).isFalse();
    }

    @Test
    void lockEndsAfterLockDuration() {
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        clock.advance(Duration.ofMinutes(5).minusSeconds(1));
        assertThat(throttle.acquireLogin("owner", "198.51.100.7").admitted()).isFalse();
        clock.advance(Duration.ofSeconds(2));
        assertThat(login("owner", "198.51.100.7", Outcome.FAILURE)).isTrue();   // window restarted at expiry
        assertThat(login("owner", "198.51.100.8", Outcome.FAILURE)).isTrue();
    }

    @Test
    void attemptsWhileLockedAreNotCounted() {
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        for (int i = 0; i < 20; i++) {
            assertThat(throttle.acquireLogin("owner", "198.51.100." + i).admitted()).isFalse();
        }
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertThat(throttle.acquireLogin("owner", "198.51.100.99").admitted()).isTrue();
    }

    @Test
    void windowExpiryResetsTheCount() {
        login("owner", "203.0.113.1", Outcome.FAILURE);
        login("owner", "203.0.113.2", Outcome.FAILURE);
        clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        login("owner", "203.0.113.3", Outcome.FAILURE);
        login("owner", "203.0.113.4", Outcome.FAILURE);
        assertThat(throttle.acquireLogin("owner", "203.0.113.5").admitted()).isTrue();
    }

    @Test
    void successResetsTheUsernameCounter() {
        login("owner", "203.0.113.1", Outcome.FAILURE);
        login("owner", "203.0.113.2", Outcome.FAILURE);
        login("owner", "203.0.113.3", Outcome.SUCCESS);
        login("owner", "203.0.113.4", Outcome.FAILURE);
        login("owner", "203.0.113.5", Outcome.FAILURE);
        assertThat(throttle.acquireLogin("owner", "203.0.113.6").admitted()).isTrue();
    }

    @Test
    void successesNeverLock() {
        for (int i = 0; i < 50; i++) {
            assertThat(login("owner", "203.0.113.1", Outcome.SUCCESS)).isTrue();
        }
    }

    @Test
    void nonCountingOutcomesNeverLock() {
        for (int i = 0; i < 50; i++) {
            assertThat(login("owner", "203.0.113.1", Outcome.NONE)).isTrue();
        }
        assertThat(throttle.trackedEntries()).isZero();
    }

    @Test
    void ipLockIsIndependentOfTheUsernameLock() {
        for (int i = 0; i < 5; i++) {
            login("user" + i, "203.0.113.1", Outcome.FAILURE);   // 5 usernames, one IP
        }
        assertThat(throttle.acquireLogin("someone-else", "203.0.113.1").admitted()).isFalse();
        assertThat(login("user0", "198.51.100.1", Outcome.SUCCESS)).isTrue();   // same username elsewhere
    }

    @Test
    void usernameLockAppliesAcrossIps() {
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", "198.51.100.1").admitted()).isFalse();
        assertThat(login("other", "203.0.113.0", Outcome.SUCCESS)).isTrue();   // the IPs are not locked
    }

    @Test
    void knownGoodNetworkBypassesTheUsernameLockButNotTheIpLock() {
        login("owner", "192.0.2.10", Outcome.SUCCESS);
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", "198.51.100.1").admitted()).isFalse();
        assertThat(login("owner", "192.0.2.10", Outcome.NONE)).isTrue();   // known network still admitted

        // Lock both the username and the known network's IP: then the pair is rejected as well.
        for (int i = 0; i < 5; i++) {
            login("guess" + i, "192.0.2.10", Outcome.FAILURE);
        }
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", "192.0.2.10").admitted()).isFalse();
    }

    @Test
    void knownGoodNetworkSurvivesOtherUsersLockingTheSharedIp() {
        login("owner", "192.0.2.10", Outcome.SUCCESS);
        for (int i = 0; i < 5; i++) {
            login("guess" + i, "192.0.2.10", Outcome.FAILURE);   // shared NAT: someone else trips the IP lock
        }
        assertThat(throttle.acquireLogin("stranger", "192.0.2.10").admitted()).isFalse();
        assertThat(throttle.acquireLogin("owner", "192.0.2.10").admitted()).isTrue();
    }

    @Test
    void knownGoodExpiresAfterTheTtl() {
        login("owner", "192.0.2.10", Outcome.SUCCESS);
        clock.advance(Duration.ofDays(30).plusSeconds(1));
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", "192.0.2.10").admitted()).isFalse();
    }

    @Test
    void inFlightAttemptsCountTowardsTheHardBound() {
        List<Admission> open = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Admission a = throttle.acquireLogin("owner", "203.0.113." + i);
            assertThat(a.admitted()).isTrue();
            open.add(a);
        }
        assertThat(throttle.acquireLogin("owner", "203.0.113.9").admitted()).isFalse();
        open.forEach(a -> throttle.complete(a.ticket(), Outcome.SUCCESS));
        assertThat(throttle.acquireLogin("owner", "203.0.113.9").admitted()).isTrue();
    }

    @Test
    void parallelAttemptsNeverExceedTheBound() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            String ip = "203.0.113." + i;
            results.add(pool.submit(() -> {
                start.await();
                return throttle.acquireLogin("owner", ip).admitted();   // never completed: all stay in flight
            }));
        }
        start.countDown();
        int admitted = 0;
        for (Future<Boolean> f : results) {
            admitted += f.get() ? 1 : 0;
        }
        pool.shutdown();
        assertThat(admitted).isEqualTo(3);
    }

    @Test
    void successDuringAnotherInFlightAttemptKeepsTheBookkeeping() {
        Admission first = throttle.acquireLogin("owner", "203.0.113.1");
        Admission second = throttle.acquireLogin("owner", "203.0.113.2");
        throttle.complete(first.ticket(), Outcome.SUCCESS);
        throttle.complete(second.ticket(), Outcome.FAILURE);
        throttle.complete(second.ticket(), Outcome.FAILURE);   // a second completion of a ticket is ignored
        assertThat(throttle.peek("user", "owner").inFlight()).isZero();
        assertThat(throttle.peek("user", "owner").failures()).isEqualTo(1);
    }

    @Test
    void completionAfterClearDoesNotRecreateEntries() {
        Admission a = throttle.acquireLogin("owner", "203.0.113.1");
        throttle.clear();
        throttle.complete(a.ticket(), Outcome.FAILURE);
        assertThat(throttle.trackedEntries()).isZero();
    }

    @Test
    void ipv6AddressesAreAggregatedToTheirSlash64() {
        for (int i = 1; i <= 5; i++) {
            login("user" + i, "2001:db8:1:2::" + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("fresh", "2001:db8:1:2:ffff::1").admitted()).isFalse();
        assertThat(throttle.acquireLogin("fresh", "2001:db8:1:3::1").admitted()).isTrue();
    }

    @Test
    void missingIpOnlyUsesTheUsernameKey() {
        for (int i = 0; i < 3; i++) {
            login("owner", null, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", null).admitted()).isFalse();
        assertThat(throttle.acquireLogin("other", null).admitted()).isTrue();
    }

    @Test
    void hugeUsernamesAreStoredAsFixedSizeKeys() {
        String huge = "x".repeat(1_000_000);
        assertThat(throttle.key("user", huge)).isEqualTo(throttle.key("user", huge));
        assertThat(throttle.key("user", huge)).isNotEqualTo(throttle.key("user", huge + "y"));
        // Salted per process: another instance places the same input elsewhere.
        assertThat(new LoginThrottle(props, clock).key("user", "owner")).isNotEqualTo(throttle.key("user", "owner"));
        assertThat(LoginThrottle.Key.class.getRecordComponents()).hasSize(4);   // four longs, whatever the input
    }

    @Test
    void fullMapOfLockedEntriesSendsNewKeysToTheThrottledOverflowKey() {
        props.setMaxEntries(4);
        props.setUser(new LoginThrottleProperties.Limits(1, Duration.ofMinutes(15), Duration.ofMinutes(5)));
        props.setIp(new LoginThrottleProperties.Limits(1000, Duration.ofMinutes(15), Duration.ofMinutes(15)));
        for (int i = 0; i < 4; i++) {
            login("locked" + i, null, Outcome.FAILURE);
        }
        assertThat(login("new-user", null, Outcome.FAILURE)).isTrue();          // throttled on its shard
        int shard = throttle.overflowShard("user", "new-user");
        assertThat(throttle.peekOverflow("user", shard)).isNotNull();
        String sameShard = otherUsername(shard, true);
        String otherShard = otherUsername(shard, false);
        assertThat(throttle.acquireLogin(sameShard, null).admitted()).isFalse();   // that shard is locked
        // A legitimate new user on another shard (and from another IP) still gets in.
        assertThat(login(otherShard, "198.51.100.200", Outcome.SUCCESS)).isTrue();
        for (int i = 0; i < 4; i++) {
            assertThat(throttle.acquireLogin("locked" + i, null).admitted()).isFalse();
        }
    }

    private String otherUsername(int shard, boolean same) {
        for (int i = 0; ; i++) {
            String candidate = "candidate" + i;
            if ((throttle.overflowShard("user", candidate) == shard) == same) {
                return candidate;
            }
        }
    }

    @Test
    void aSuccessNeverResetsAnOverflowShard() {
        props.setMaxEntries(4);
        props.setUser(new LoginThrottleProperties.Limits(2, Duration.ofMinutes(15), Duration.ofMinutes(5)));
        for (int i = 0; i < 4; i++) {   // fill the table with locked entries
            login("locked" + i, null, Outcome.FAILURE);
            login("locked" + i, null, Outcome.FAILURE);
        }
        int shard = throttle.overflowShard("user", "guess-a");
        login("guess-a", null, Outcome.FAILURE);
        login(otherUsername(shard, true), null, Outcome.SUCCESS);   // a valid account on the same shard
        assertThat(throttle.peekOverflow("user", shard).failures()).isEqualTo(1);
        login("guess-a", null, Outcome.FAILURE);
        assertThat(throttle.peekOverflow("user", shard).lockedAt(clock.millis())).isTrue();
    }

    @Test
    void fullScanFindsAnEvictableEntryOutsideTheSample() {
        props.setMaxEntries(40);
        props.setUser(new LoginThrottleProperties.Limits(1, Duration.ofMinutes(15), Duration.ofMinutes(5)));
        for (int i = 0; i < 39; i++) {
            login("locked" + i, null, Outcome.FAILURE);   // locked: never evictable
        }
        Admission open = throttle.acquireLogin("in-flight-free", null);   // the 40th entry, then idle-able
        props.setUser(new LoginThrottleProperties.Limits(5, Duration.ofMinutes(15), Duration.ofMinutes(5)));
        throttle.complete(open.ticket(), Outcome.FAILURE);   // 1 failure, not locked: the only evictable one
        login("newcomer", null, Outcome.FAILURE);
        assertThat(throttle.peek("user", "newcomer")).isNotNull();   // tracked under its own key
    }

    @Test
    void fullMapEvictsAnUnlockedEntry() {
        props.setMaxEntries(4);
        for (int i = 0; i < 4; i++) {
            login("one-failure" + i, null, Outcome.FAILURE);
        }
        login("new-user", null, Outcome.FAILURE);
        assertThat(throttle.peek("user", "new-user")).isNotNull();
        assertThat(throttle.trackedEntries()).isLessThanOrEqualTo(4);
    }

    @Test
    void purgeRemovesExpiredEntries() {
        login("owner", "203.0.113.1", Outcome.FAILURE);
        client("device-service", "203.0.113.1", "wrong", Outcome.FAILURE);
        clock.advance(Duration.ofMinutes(16));
        throttle.purgeExpired();
        assertThat(throttle.trackedEntries()).isZero();
    }

    @Test
    void lockWarningNamesNeitherUsernameNorIp(CapturedOutput out) {
        for (int i = 0; i < 3; i++) {
            login("secret-looking-name", "203.0.113.77", Outcome.FAILURE);
        }
        assertThat(out.getAll()).contains("Login throttle: username locked for 300 s after 3 failed attempts")
                .doesNotContain("secret-looking-name").doesNotContain("203.0.113.77");
    }

    @Test
    void clientLocksPerIpAndClientId() {
        for (int i = 0; i < 3; i++) {
            assertThat(client("device-service", "203.0.113.1", "wrong", Outcome.FAILURE)).isTrue();
        }
        Admission locked = throttle.acquireClient("device-service", "203.0.113.1", "right");
        assertThat(locked.admitted()).isFalse();
        assertThat(locked.retryAfter()).isEqualTo(Duration.ofMinutes(5));
        assertThat(client("device-service", "198.51.100.1", "right", Outcome.SUCCESS)).isTrue();   // other IP
        assertThat(client("furchert-ch", "203.0.113.1", "right", Outcome.SUCCESS)).isTrue();      // other client
    }

    @Test
    void clientConcurrencyIsBoundedUntilTheSecretIsKnown() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            results.add(pool.submit(() -> {
                start.await();
                return throttle.acquireClient("furchert-ch", "10.42.0.5", "guess").admitted();
            }));
        }
        start.countDown();
        int admitted = 0;
        for (Future<Boolean> f : results) {
            admitted += f.get() ? 1 : 0;
        }
        pool.shutdown();
        assertThat(admitted).isEqualTo(3);
        throttle.clear();
        assertThat(client("furchert-ch", "10.42.0.5", "right", Outcome.SUCCESS)).isTrue();
        for (int i = 0; i < 20; i++) {   // a known secret is never bounded
            assertThat(throttle.acquireClient("furchert-ch", "10.42.0.5", "right").admitted()).isTrue();
        }
    }

    @Test
    void aRotatedSecretLosesItsExemption() {
        assertThat(client("device-service", "10.42.0.7", "old", Outcome.SUCCESS)).isTrue();
        // The client's secret was rotated: the old secret now fails, and stops being exempt.
        assertThat(client("device-service", "10.42.0.7", "old", Outcome.FAILURE)).isTrue();
        for (int i = 0; i < 2; i++) {
            client("device-service", "10.42.0.7", "old", Outcome.FAILURE);
        }
        assertThat(throttle.acquireClient("device-service", "10.42.0.7", "old").admitted()).isFalse();
    }

    @Test
    void aKnownNetworkIsStillBoundedByAttemptsInFlight() {
        login("owner", "192.0.2.10", Outcome.SUCCESS);
        int admitted = 0;
        for (int i = 0; i < 20; i++) {   // never completed: all stay in flight
            admitted += throttle.acquireLogin("owner", "192.0.2.10").admitted() ? 1 : 0;
        }
        assertThat(admitted).isEqualTo(3);
    }

    @Test
    void aSuccessNeverLiftsAnActiveLock() {
        login("owner", "192.0.2.10", Outcome.SUCCESS);
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(login("owner", "192.0.2.10", Outcome.SUCCESS)).isTrue();   // known network
        assertThat(throttle.acquireLogin("owner", "198.51.100.1").admitted()).isFalse();   // still locked
    }

    @Test
    void anotherAccountCannotPushTheOwnersNetworksOut() {
        login("owner", "192.0.2.10", Outcome.SUCCESS);
        for (int i = 0; i <= LoginThrottle.MAX_KNOWN_GOOD_USERS; i++) {   // one account, more networks than the cap
            login("attacker", "10." + (i / 65536) + "." + ((i / 256) % 256) + "." + (i % 256), Outcome.SUCCESS);
        }
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(login("owner", "192.0.2.10", Outcome.NONE)).isTrue();
    }

    @Test
    void eachUsernameKeepsItsMostRecentNetworks() {
        for (int i = 1; i <= LoginThrottle.KNOWN_GOOD_NETWORKS_PER_USER + 1; i++) {
            login("owner", "192.0.2." + i, Outcome.SUCCESS);
            clock.advance(Duration.ofSeconds(1));
        }
        for (int i = 0; i < 3; i++) {
            login("owner", "203.0.113." + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireLogin("owner", "192.0.2.1").admitted()).isFalse();   // oldest dropped
        assertThat(throttle.acquireLogin("owner", "192.0.2.9").admitted()).isTrue();
    }

    @Test
    void rejectionsAreReportedAsCountsOnly(CapturedOutput out) {
        for (int i = 0; i < 3; i++) {
            login("secret-looking-name", "203.0.113.77", Outcome.FAILURE);
        }
        for (int i = 0; i < 4; i++) {
            throttle.acquireLogin("secret-looking-name", "203.0.113.78");
        }
        throttle.purgeExpired();
        assertThat(out.getAll()).contains("Login throttle: rejected 4 attempts since the last report")
                .contains("username: 4 locked").doesNotContain("secret-looking-name").doesNotContain("203.0.113.7");
    }

    @Test
    void aKnownClientSecretPassesItsOwnLock(CapturedOutput out) {
        assertThat(client("claude-mcp-hub", "160.79.104.10", "the-real-secret", Outcome.SUCCESS)).isTrue();
        for (int i = 0; i < 3; i++) {
            client("claude-mcp-hub", "160.79.104.10", "guess" + i, Outcome.FAILURE);
        }
        assertThat(throttle.acquireClient("claude-mcp-hub", "160.79.104.10", "guess-again").admitted()).isFalse();
        assertThat(throttle.acquireClient("claude-mcp-hub", "160.79.104.10", "the-real-secret").admitted()).isTrue();
        assertThat(out.getAll()).contains("Login throttle: client 'claude-mcp-hub' locked")
                .doesNotContain("the-real-secret").doesNotContain("guess").doesNotContain("160.79.104.10");
    }

    @Test
    void disabledThrottleAdmitsEverything() {
        props.setEnabled(false);
        for (int i = 0; i < 10; i++) {
            assertThat(login("owner", "203.0.113.1", Outcome.FAILURE)).isTrue();
        }
        assertThat(throttle.trackedEntries()).isZero();
    }

    @Test
    void onlyCredentialFailuresCount() {
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("owner", "pw");
        assertThat(LoginThrottle.outcomeOf(new AuthenticationFailureBadCredentialsEvent(token,
                new BadCredentialsException("x")))).isEqualTo(Outcome.FAILURE);
        assertThat(LoginThrottle.outcomeOf(new AuthenticationFailureDisabledEvent(token,
                new DisabledException("x")))).isEqualTo(Outcome.FAILURE);
        assertThat(LoginThrottle.outcomeOf(new AuthenticationFailureServiceExceptionEvent(token,
                new AuthenticationServiceException("db down")))).isEqualTo(Outcome.NONE);
    }
}
