package ch.furchert.homelab.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class IdTokenRejectingValidatorTest {

    private final IdTokenRejectingValidator validator = new IdTokenRejectingValidator();

    private static Jwt.Builder token() {
        return Jwt.withTokenValue("t").header("alg", "RS256").subject("admin").claim("role", "ADMIN")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
    }

    @Test
    void acceptsAccessTokens() {
        assertThat(validator.validate(token().claim("scope", "openid profile").notBefore(Instant.now()).build())
                .hasErrors()).isFalse();
        // client_credentials / device tokens: no role, maybe no scope — still no azp
        assertThat(validator.validate(token().build()).hasErrors()).isFalse();
    }

    @Test
    void rejectsIdTokens() {
        OAuth2TokenValidatorResult result = validator.validate(token().claim("azp", "furchert-ch").build());
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).allSatisfy(e -> assertThat(e.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
    }
}
