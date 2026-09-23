package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import ch.furchert.homelab.auth.config.OidcClientProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Decides once at startup whether login-event capture and the pull endpoint are active.
 * <p>
 * Both new env vars are optional on purpose: auth-service is Flux-auto-deployed on merge and is
 * the sole IdP, so a missing Secret key must never stop the pod (all SSO would go down). When
 * either {@code LOGIN_EVENT_HMAC_KEY} or {@code DATA_SERVICE_CLIENT_SECRET} is absent the feature
 * is off and exactly one WARN line names the missing variable(s) — never their values.
 */
@Component
@Slf4j
public class LoginEventFeature {

    /** HMAC keys shorter than this make the username hash guessable; treated as absent. */
    static final int MIN_HMAC_KEY_LENGTH = 32;

    private final boolean enabled;

    public LoginEventFeature(LoginEventProperties properties, OidcClientProperties oidcClientProperties) {
        List<String> problems = new ArrayList<>();
        String key = properties.getHmacKey();
        if (key == null || key.isBlank()) {
            problems.add("LOGIN_EVENT_HMAC_KEY is not set");
        } else if (key.length() < MIN_HMAC_KEY_LENGTH) {
            problems.add("LOGIN_EVENT_HMAC_KEY is shorter than " + MIN_HMAC_KEY_LENGTH + " characters");
        }
        boolean consumerConfigured = oidcClientProperties.getClients().stream()
                .anyMatch(c -> properties.getConsumerClientId().equals(c.getClientId())
                        && c.getClientSecret() != null && !c.getClientSecret().isBlank());
        if (!consumerConfigured) {
            problems.add("client secret for '" + properties.getConsumerClientId()
                    + "' (DATA_SERVICE_CLIENT_SECRET) is not set");
        }
        this.enabled = problems.isEmpty();
        if (enabled) {
            log.info("Login-event outbox enabled (consumer client '{}')", properties.getConsumerClientId());
        } else {
            log.warn("Login-event outbox disabled: {}; logins are not recorded and "
                    + "GET /api/v1/login-events answers 503", String.join(", ", problems));
        }
    }

    public boolean isEnabled() {
        return enabled;
    }
}
