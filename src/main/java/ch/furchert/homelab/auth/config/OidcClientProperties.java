package ch.furchert.homelab.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

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
