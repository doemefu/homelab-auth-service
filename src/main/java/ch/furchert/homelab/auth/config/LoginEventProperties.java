package ch.furchert.homelab.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Login-event outbox settings (NM-4, docs/060 §7.6). The feature is enabled only when
 * {@code hmac-key} is set and the consumer client ({@code consumer-client-id}) is configured
 * with a client secret — see {@link ch.furchert.homelab.auth.service.LoginEventFeature}.
 */
@ConfigurationProperties(prefix = "app.login-events")
@Getter
@Setter
public class LoginEventProperties {

    /**
     * Key for the username HMAC (env {@code LOGIN_EVENT_HMAC_KEY}). Blank = feature disabled.
     * Must never be logged.
     */
    private String hmacKey = "";

    /**
     * The registered client that pulls the outbox. Its configured client secret doubles as the
     * "consumer provisioned" signal.
     */
    private String consumerClientId = "data-service";

    /** Rows older than this (by {@code recorded_at}) are purged. */
    private Duration ttl = Duration.ofHours(72);

    /** Rows younger than this are not served yet, so late-committing ids are never skipped. */
    private Duration settle = Duration.ofSeconds(10);

    /** Capacity of the bounded insert queue; attempts beyond it are dropped. */
    private int queueCapacity = 1000;

    private int defaultLimit = 500;

    private int maxLimit = 1000;
}
