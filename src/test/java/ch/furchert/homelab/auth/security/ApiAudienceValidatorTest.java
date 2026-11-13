package ch.furchert.homelab.auth.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ApiAudienceValidatorTest {

    private final ApiAudienceValidator validator = new ApiAudienceValidator();

    private static Jwt.Builder token() {
        return Jwt.withTokenValue("t").header("alg", "RS256").subject("admin").claim("role", "ADMIN")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
    }

    @ParameterizedTest
    @ValueSource(strings = {"furchert-ch", "device-service", "data-service"})
    void acceptsTheFirstPartyCallers(String audience) {
        assertThat(validator.validate(token().audience(List.of(audience)).build()).hasErrors()).isFalse();
        assertThat(validator.validate(token().audience(List.of("other", audience)).build()).hasErrors()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"litellm", "claude-mcp-hub", "terra1", "Furchert-CH"})
    void rejectsEveryOtherAudience(String audience) {
        OAuth2TokenValidatorResult result = validator.validate(token().audience(List.of(audience)).build());
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).allSatisfy(e -> assertThat(e.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
    }

    @Test
    void rejectsATokenWithoutAudience() {
        assertThat(validator.validate(token().build()).hasErrors()).isTrue();
    }
}
