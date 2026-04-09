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

    @Getter
    @Setter
    public static class ClientDefinition {
        private String clientId;
        private String clientSecret;
        private List<String> redirectUris = new ArrayList<>();
        private List<String> postLogoutRedirectUris = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();
    }
}
