package ch.furchert.homelab.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Failed-attempt throttle for form login and client authentication (#104), see
 * {@link ch.furchert.homelab.auth.security.LoginThrottle}. Values are read on every attempt.
 */
@ConfigurationProperties(prefix = "app.login-throttle")
@Validated
@Getter
@Setter
public class LoginThrottleProperties {

    /** Kill switch: false lets every attempt through unchecked (filter and client decorator pass through). */
    private boolean enabled = true;

    /** Per submitted username (lower-cased, trimmed), form login only. */
    @Valid
    @NotNull
    private Limits user = new Limits(10, Duration.ofMinutes(15), Duration.ofMinutes(5));

    /** Per client IP (IPv6 aggregated to its /64), form login only. */
    @Valid
    @NotNull
    private Limits ip = new Limits(20, Duration.ofMinutes(15), Duration.ofMinutes(15));

    /** Per (client IP, client_id), every client-authenticating endpoint. */
    @Valid
    @NotNull
    private Limits client = new Limits(10, Duration.ofMinutes(5), Duration.ofMinutes(5));

    /**
     * Per client_id over all sources (the client IP header is forgeable inside the cluster). Reaching
     * {@code max-failures} puts the client into strict mode for {@code lock-duration}: one failed attempt
     * per source. Never rejects a source without failures.
     */
    @Valid
    @NotNull
    private Limits clientId = new Limits(50, Duration.ofMinutes(5), Duration.ofMinutes(5));

    /** A (username, network) pair with a successful login is exempt from the username lock this long. */
    @NotNull
    @DurationMin(seconds = 1)
    private Duration knownGoodTtl = Duration.ofDays(30);

    /** Upper bound of tracked username keys and of tracked IP keys (each). */
    @Positive
    private int maxEntries = 30_000;

    @Getter
    @Setter
    public static class Limits {

        @Positive
        private int maxFailures;

        /** At least 1 s: Boot reads a unit-less value as milliseconds, which would disable the lock. */
        @NotNull
        @DurationMin(seconds = 1)
        private Duration window;

        @NotNull
        @DurationMin(seconds = 1)
        private Duration lockDuration;

        public Limits() {
        }

        public Limits(int maxFailures, Duration window, Duration lockDuration) {
            this.maxFailures = maxFailures;
            this.window = window;
            this.lockDuration = lockDuration;
        }
    }
}
