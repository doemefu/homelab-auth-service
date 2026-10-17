package ch.furchert.homelab.auth.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Rejects ID tokens presented as bearer tokens. Access and ID tokens are signed with the same key and
 * both carry the {@code role} claim, so a signature-and-expiry check alone lets an ID token, which every
 * OIDC client receives and furchert-ch's logout puts in a redirect URL, act as an access token for up to
 * its 30 minute lifetime.
 * <p>
 * Spring Authorization Server's {@code JwtGenerator} adds {@code azp} to every ID token and to no access
 * token, and the token customizer never adds it, so its presence is the marker.
 */
public class IdTokenRejectingValidator implements OAuth2TokenValidator<Jwt> {

    static final String AZP = "azp";

    private static final OAuth2Error ID_TOKEN = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
            "ID tokens are not accepted as bearer tokens", null);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        return token.hasClaim(AZP) ? OAuth2TokenValidatorResult.failure(ID_TOKEN) : OAuth2TokenValidatorResult.success();
    }
}
