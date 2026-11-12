package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** User passwords at the configured cost, client secrets at cost 10; both verify every stored format (#150). */
class PasswordEncodersTest {

    private static final String PW = "a-throwaway-test-passphrase";
    private static final String COST_10 = new BCryptPasswordEncoder(10).encode(PW);

    private final PasswordEncoder users = new SecurityConfig().passwordEncoder(12);
    private final PasswordEncoder clients = new SecurityConfig().clientSecretEncoder().encoder();

    @Test
    void userEncoder_encodesAtTheConfiguredCost() {
        assertThat(users.encode(PW)).matches("\\{bcrypt}\\$2a\\$12\\$.{53}");
        assertThat(new SecurityConfig().passwordEncoder(11).encode(PW)).startsWith("{bcrypt}$2a$11$");
    }

    @Test
    void clientEncoder_encodesAtCost10() {
        assertThat(clients.encode(PW)).matches("\\{bcrypt}\\$2a\\$10\\$.{53}");
    }

    @Test
    void bothVerifyLegacyFormats() {
        for (PasswordEncoder encoder : new PasswordEncoder[] {users, clients}) {
            assertThat(encoder.matches(PW, "{bcrypt}" + COST_10)).isTrue();
            assertThat(encoder.matches(PW, COST_10)).isTrue();               // unprefixed legacy hash
            assertThat(encoder.matches(PW, "{noop}" + PW)).isTrue();
            assertThat(encoder.matches(PW + "x", "{bcrypt}" + COST_10)).isFalse();
        }
    }

    @Test
    void userEncoder_marksLowerCostUnprefixedAndNoopAsOutdated() {
        assertThat(users.upgradeEncoding("{bcrypt}" + COST_10)).isTrue();
        assertThat(users.upgradeEncoding(COST_10)).isTrue();
        assertThat(users.upgradeEncoding("{noop}" + PW)).isTrue();
        assertThat(users.upgradeEncoding(users.encode(PW))).isFalse();
    }

    @Test
    void clientEncoder_keepsCost10_upgradesNoop() {
        assertThat(clients.upgradeEncoding("{bcrypt}" + COST_10)).isFalse();
        assertThat(clients.upgradeEncoding("{noop}" + PW)).isTrue();
    }

    @Test
    void userStrengthOutsideTheAllowedRange_failsStartUp() {
        assertThatThrownBy(() -> new SecurityConfig().passwordEncoder(9)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SecurityConfig().passwordEncoder(17)).isInstanceOf(IllegalArgumentException.class);
    }
}
