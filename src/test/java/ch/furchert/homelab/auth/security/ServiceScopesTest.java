package ch.furchert.homelab.auth.security;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ServiceScopesTest {

    @ParameterizedTest
    @ValueSource(strings = {"netmon:read", "analytics:write", "analytics:read", "login-events:read", "clients:admin"})
    void serviceScopes(String scope) {
        assertThat(ServiceScopes.isServiceScope(scope)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"openid", "profile", "email", "mail:read", "calendar:read", "club:read", "mqtt:pub",
            "mqtt:sub", "netmon", "xnetmon:read", "clients:admins", "Netmon:read", ""})
    void otherScopes(String scope) {
        assertThat(ServiceScopes.isServiceScope(scope)).isFalse();
    }

    @Test
    void serviceScopesInFiltersAndHandlesNull() {
        assertThat(ServiceScopes.serviceScopesIn(List.of("openid", "netmon:read", "email", "clients:admin")))
                .containsExactly("netmon:read", "clients:admin");
        assertThat(ServiceScopes.serviceScopesIn(List.of("openid", "profile"))).isEmpty();
        assertThat(ServiceScopes.serviceScopesIn(null)).isEmpty();
        assertThat(ServiceScopes.isServiceScope(null)).isFalse();
    }
}
