package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.List;

/**
 * First converter on /oauth2/token: rejects a code exchange or refresh whose resource parameter is
 * not allowed for the authenticated client with 400 invalid_target (docs/080 §4.2), and every such
 * request of a client marked audience-bound whose configuration is missing with 400
 * unauthorized_client. Returns null in every other case so the default converters handle the
 * request unchanged.
 * <p>
 * Must never be a Spring bean (no @Component): the resource-server configuration adopts any
 * AuthenticationConverter bean in place of its bearer-token converter, for every resource-server
 * chain of this application. AuthorizationServerConfig constructs it and registers it only on the
 * token endpoint; a test asserts that no bean of this type exists.
 */
@RequiredArgsConstructor
@Slf4j
public class ResourceIndicatorTokenRequestGuard implements AuthenticationConverter {

    private final OidcClientProperties properties;
    private final ResourceIndicatorPolicy policy;

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)
                && !AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }
        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2ClientAuthenticationToken client)
                || client.getRegisteredClient() == null) {
            return null;
        }
        RegisteredClient registeredClient = client.getRegisteredClient();
        if (properties.isAudienceBoundWithoutDefinition(registeredClient)) {
            log.warn("Client '{}' is marked audience-bound but has no configured audience; request rejected",
                    registeredClient.getClientId());
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                    "This client is not configured", null));
        }
        // Query string and form body both count: stricter than SAS, which reads token parameters from the body only.
        String[] resources = request.getParameterValues(ResourceIndicatorPolicy.PARAMETER);
        if (!policy.isAllowed(registeredClient, resources == null ? List.of() : List.of(resources))) {
            throw new OAuth2AuthenticationException(new OAuth2Error(ResourceIndicatorPolicy.INVALID_TARGET,
                    "The requested resource is not valid for this client", null));
        }
        return null;
    }
}
