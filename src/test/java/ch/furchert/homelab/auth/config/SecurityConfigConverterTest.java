package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigConverterTest {

    private final JwtAuthenticationConverter converter = SecurityConfig.jwtAuthenticationConverter();

    /**
     * Spring Security 7 injects a FactorGrantedAuthority(FACTOR_BEARER) into every
     * resource-server JWT authentication; the converter-emitted authorities live
     * alongside it. The tests focus on what the project's converter contributes.
     */
    private static List<String> projectAuthorities(AbstractAuthenticationToken auth) {
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_") || a.startsWith("SCOPE_"))
                .toList();
    }

    @Test
    void emitsRoleAndScopeAuthorities() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .claim("role", "ADMIN")
                .claim("scope", "openid profile email")
                .build();

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(projectAuthorities(auth))
                .contains("ROLE_ADMIN", "SCOPE_openid", "SCOPE_profile", "SCOPE_email");
    }

    @Test
    void ssoJwtDoesNotGrantClientsAdmin() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .claim("role", "USER")
                .claim("scope", "openid profile email")
                .build();

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(projectAuthorities(auth))
                .doesNotContain("SCOPE_clients:admin");
    }

    @Test
    void clientCredentialsJwtWithClientsAdminScope() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .claim("scope", "clients:admin")
                .build();

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(projectAuthorities(auth))
                .contains("SCOPE_clients:admin");
    }

    @Test
    void jwtMissingBothClaimsDoesNotThrow() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .claim("sub", "anonymous")
                .build();

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(projectAuthorities(auth)).isEmpty();
    }

    @Test
    void jwtWithRoleButNoScope() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .claim("role", "ADMIN")
                .build();

        AbstractAuthenticationToken auth = converter.convert(jwt);

        assertThat(projectAuthorities(auth))
                .containsExactly("ROLE_ADMIN");
    }
}
