package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Keyed username hash for the login-event outbox (docs/060 §7.6):
 * lowercase hex of {@code HMAC-SHA256(key, lowercase(trim(username)))}.
 * <p>
 * Keyed because the username space is tiny (an unkeyed hash is reversible by dictionary) and
 * because users sometimes type a password into the username field. The key is the UTF-8 bytes of
 * {@code LOGIN_EVENT_HMAC_KEY} and stays in auth-service. This class only computes hashes and
 * never compares them, so no constant-time comparison is involved.
 */
@Component
public class UsernameHmac {

    private static final String ALGORITHM = "HmacSHA256";

    private final SecretKeySpec key;

    public UsernameHmac(LoginEventProperties properties) {
        String raw = properties.getHmacKey();
        this.key = raw == null || raw.isBlank()
                ? null
                : new SecretKeySpec(raw.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    /**
     * @throws IllegalStateException if no key is configured (callers check the feature flag first)
     */
    public String hash(String username) {
        String normalized = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        return hmacHex(normalized);
    }

    String hmacHex(String message) {
        if (key == null) {
            throw new IllegalStateException("Login-event HMAC key is not configured");
        }
        try {
            // Mac instances are not thread-safe; a fresh one per call is cheap next to a BCrypt check.
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return HexFormat.of().formatHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
