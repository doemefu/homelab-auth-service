package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.util.function.Consumer;

/**
 * Runs after SAS's default authorization-request validator (redirect_uri, scope) for every client.
 * Rejects a client marked audience-bound whose configuration is missing with an access_denied error
 * redirect, and a resource parameter that is not allowed for the client with an invalid_target error
 * redirect. Registered on the authorization endpoint only; if pushed authorization requests (PAR)
 * are ever enabled, it must be added to the PAR endpoint as well.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ClientAuthorizationRequestValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    private final OidcClientProperties properties;
    private final ResourceIndicatorPolicy resourcePolicy;

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken request = context.getAuthentication();
        RegisteredClient client = context.getRegisteredClient();
        String clientId = client.getClientId();
        if (properties.isAudienceBoundWithoutDefinition(client)) {
            log.warn("Client '{}' is marked audience-bound but has no configured audience; request rejected", clientId);
            throw error(OAuth2ErrorCodes.ACCESS_DENIED, "This client is not configured", request);
        }
        if (!resourcePolicy.isAllowed(client, ResourceIndicatorPolicy.values(
                request.getAdditionalParameters().get(ResourceIndicatorPolicy.PARAMETER)))) {
            throw error(ResourceIndicatorPolicy.INVALID_TARGET, "The requested resource is not valid for this client", request);
        }
    }

    private static OAuth2AuthorizationCodeRequestAuthenticationException error(
            String code, String description, OAuth2AuthorizationCodeRequestAuthenticationToken request) {
        // Carrying the request token lets SAS redirect the error to the (already validated) redirect_uri.
        return new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(code, description, null), request);
    }
}
