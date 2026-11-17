package ch.furchert.homelab.auth.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Accepts a bearer token on the admin API ({@code /api/v1/**}) only if its {@code aud} names one of the
 * first-party clients that call it (#153). Spring Authorization Server sets {@code aud} to the requesting
 * client's id, so tokens issued to any other relying party are refused even when they carry an admin role.
 * Interim step until resource-scoped audiences exist (#101).
 * <ul>
 *   <li>{@code furchert-ch}: the signed-in admin's access token for {@code /dashboard/auth};</li>
 *   <li>{@code device-service}: its {@code client_credentials} token for {@code /api/v1/clients};</li>
 *   <li>{@code data-service}: its {@code client_credentials} token for {@code /api/v1/login-events}.</li>
 * </ul>
 */
public class ApiAudienceValidator implements OAuth2TokenValidator<Jwt> {

    public static final Set<String> ALLOWED_AUDIENCES = Set.of("furchert-ch", "device-service", "data-service");

    private static final OAuth2Error NOT_FOR_THIS_API = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
            "The token audience is not accepted by this API", null);

    /** {@code decoder} with this validator applied after it (its own validators run first). */
    public static JwtDecoder restrict(JwtDecoder decoder) {
        ApiAudienceValidator validator = new ApiAudienceValidator();
        return token -> {
            Jwt jwt = decoder.decode(token);
            OAuth2TokenValidatorResult result = validator.validate(jwt);
            if (result.hasErrors()) {
                throw new JwtValidationException(NOT_FOR_THIS_API.getDescription(), result.getErrors());
            }
            return jwt;
        };
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        List<String> audience = token.getAudience();
        return audience != null && !Collections.disjoint(audience, ALLOWED_AUDIENCES)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(NOT_FOR_THIS_API);
    }
}
