package ch.furchert.homelab.auth.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Client secrets are stored as {bcrypt} values with cost 10 (docs/080 §9.5, #107); htpasswd produces
 * the $2y$ revision. The production password encoder must accept it, and $2a$/$2b$ as well.
 */
class ClientSecretHashFormatTest {

    private final PasswordEncoder encoder = new SecurityConfig().passwordEncoder();

    @ParameterizedTest
    @EnumSource(value = BCryptPasswordEncoder.BCryptVersion.class, names = {"$2Y", "$2A", "$2B"})
    void bcryptIdWithCost10IsAccepted(BCryptPasswordEncoder.BCryptVersion version) {
        String throwaway = UUID.randomUUID().toString();           // generated here, never a real secret
        String hash = new BCryptPasswordEncoder(version, 10).encode(throwaway);
        assertThat(hash).matches("\\$2[ayb]\\$10\\$[./0-9A-Za-z]{53}");
        assertThat(encoder.matches(throwaway, "{bcrypt}" + hash)).isTrue();
        assertThat(encoder.matches(throwaway + "x", "{bcrypt}" + hash)).isFalse();
    }
}
