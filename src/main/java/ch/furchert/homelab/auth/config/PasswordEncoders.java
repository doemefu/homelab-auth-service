package ch.furchert.homelab.auth.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

/**
 * The two password encoders (#150). Both have the same id map: {@code {bcrypt}} for new values and
 * {@code {noop}} for configured client secrets that are not hashed yet (homelab#154). Unprefixed
 * legacy bcrypt hashes still match. They differ only in the bcrypt cost:
 * <ul>
 *   <li>user passwords: {@code app.password.bcrypt-strength} (default 12), the {@link PasswordEncoder} bean;</li>
 *   <li>OAuth client secrets: cost 10, {@link ClientSecretEncoder}. They are long random values, so a higher
 *       cost adds CPU on every token request and no protection. Spring Authorization Server re-encodes a
 *       client secret whose cost is below the encoder's after each successful client authentication, so sharing
 *       the user encoder would silently rewrite every stored client secret.</li>
 * </ul>
 * A stored value with a lower cost, no prefix or {@code {noop}} counts as outdated
 * ({@code upgradeEncoding}), and is re-encoded at the next successful login or client authentication.
 */
public final class PasswordEncoders {

    public static final int CLIENT_SECRET_BCRYPT_STRENGTH = 10;

    private PasswordEncoders() {
    }

    @SuppressWarnings("deprecation") // NoOpPasswordEncoder: only to verify {noop} values, never used for encoding
    static DelegatingPasswordEncoder delegating(int bcryptStrength) {
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(bcryptStrength);
        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder("bcrypt",
                Map.of("bcrypt", bcrypt, "noop", NoOpPasswordEncoder.getInstance()));
        encoder.setDefaultPasswordEncoderForMatches(bcrypt);
        return encoder;
    }

    /** OAuth client secrets: bcrypt cost {@value #CLIENT_SECRET_BCRYPT_STRENGTH}. */
    public static PasswordEncoder clientSecrets() {
        return delegating(CLIENT_SECRET_BCRYPT_STRENGTH);
    }
}
