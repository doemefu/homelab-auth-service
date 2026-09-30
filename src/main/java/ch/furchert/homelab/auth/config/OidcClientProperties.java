package ch.furchert.homelab.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@ConfigurationProperties(prefix = "app.oidc")
@Getter
@Setter
public class OidcClientProperties {

    private String issuer;
    private List<ClientDefinition> clients = new ArrayList<>();
    private DeviceClientsProperties deviceClients = new DeviceClientsProperties();

    @Getter
    @Setter
    public static class ClientDefinition {
        private String clientId;
        private String clientSecret;
        private List<String> redirectUris = new ArrayList<>();
        private List<String> postLogoutRedirectUris = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();
        /**
         * OAuth2 grant types the client may use. Defaults to authorization_code +
         * refresh_token (the existing SSO pattern); the device-service entry adds
         * client_credentials so it can call the admin API service-to-service.
         */
        private List<String> grantTypes = new ArrayList<>(List.of("authorization_code", "refresh_token"));
        /**
         * Token-endpoint client authentication methods (SAS values). Defaults to HTTP Basic only,
         * which every existing client uses; claude-mcp-hub adds client_secret_post (docs/080 §4.1).
         */
        private List<String> clientAuthenticationMethods = new ArrayList<>(List.of("client_secret_basic"));
        /** false = rotate the refresh token on every refresh grant. Default true (no rotation). */
        private boolean reuseRefreshTokens = true;
        /** Show the consent page before issuing a code. Default false. */
        private boolean requireAuthorizationConsent = false;
        /** Per-client access-token lifetime; null = app.jwt.access-token-expiry. */
        private Duration accessTokenTimeToLive;
        /**
         * When set, this client's access tokens are bound to one resource server: header typ at+jwt,
         * aud = [this value], a client_id claim and no role claim (docs/080 §4.2). Null = default shape.
         */
        private String accessTokenAudience;
        /** Accepted RFC 8707 resource values. Empty = the parameter is ignored (default). */
        private List<String> allowedResources = new ArrayList<>();
        /** true = only allowedUsers may obtain an authorization code; an empty list rejects everyone. */
        private boolean restrictToAllowedUsers = false;
        /** Exact, case-sensitive usernames; a comma-separated env value binds to this list. */
        private List<String> allowedUsers = new ArrayList<>();
    }

    /**
     * Custom client setting the seeder writes for every client with an access-token audience. A plain
     * Boolean, so it survives the JDBC client store's JSON round trip on every token request.
     */
    public static final String AUDIENCE_BOUND_SETTING = "settings.client.homelab.audience-bound";

    public Optional<ClientDefinition> findClient(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        return clients.stream().filter(c -> clientId.equals(c.getClientId())).findFirst();
    }

    /**
     * True for a registered client that was seeded as audience-bound but whose definition, or its
     * access-token-audience, is no longer configured (entry removed or renamed). Callers refuse every
     * authorization and token request for such a client instead of falling back to the default token
     * shape (fail closed, #107). Unmarked clients are never affected.
     */
    public boolean isAudienceBoundWithoutDefinition(RegisteredClient client) {
        return Boolean.TRUE.equals(client.getClientSettings().<Object>getSetting(AUDIENCE_BOUND_SETTING))
                && findClient(client.getClientId())
                        .map(ClientDefinition::getAccessTokenAudience)
                        .filter(audience -> !audience.isBlank())
                        .isEmpty();
    }

    @Getter
    @Setter
    public static class DeviceClientsProperties {
        /**
         * Access-token TTL applied to newly created device clients.
         */
        private long accessTokenTtlSeconds = 3600;
        /**
         * Scopes a device client is allowed to request.
         */
        private List<String> allowedScopes = new ArrayList<>(List.of("mqtt:pub", "mqtt:sub"));
    }
}
