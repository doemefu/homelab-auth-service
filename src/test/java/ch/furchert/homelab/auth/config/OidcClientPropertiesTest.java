package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = OidcClientPropertiesTest.Config.class)
@TestPropertySource(properties = {
    "app.oidc.issuer=https://auth.furchert.ch",
    "app.oidc.clients[0].client-id=grafana",
    "app.oidc.clients[0].client-secret={bcrypt}$2a$10$hashedvalue",
    "app.oidc.clients[0].redirect-uris[0]=https://grafana.furchert.ch/login/generic_oauth",
    "app.oidc.clients[0].post-logout-redirect-uris[0]=https://grafana.furchert.ch",
    "app.oidc.clients[0].scopes[0]=openid",
    "app.oidc.clients[0].scopes[1]=profile",
    "app.oidc.clients[0].scopes[2]=email"
})
class OidcClientPropertiesTest {

    @EnableConfigurationProperties(OidcClientProperties.class)
    static class Config {}

    @Autowired
    OidcClientProperties props;

    @Test
    void loadsIssuer() {
        assertThat(props.getIssuer()).isEqualTo("https://auth.furchert.ch");
    }

    @Test
    void loadsClientId() {
        assertThat(props.getClients()).hasSize(1);
        assertThat(props.getClients().get(0).getClientId()).isEqualTo("grafana");
    }

    @Test
    void loadsClientSecret() {
        assertThat(props.getClients().get(0).getClientSecret()).startsWith("{bcrypt}");
    }

    @Test
    void loadsRedirectUris() {
        assertThat(props.getClients().get(0).getRedirectUris())
            .containsExactly("https://grafana.furchert.ch/login/generic_oauth");
    }

    @Test
    void loadsPostLogoutRedirectUris() {
        assertThat(props.getClients().get(0).getPostLogoutRedirectUris())
            .containsExactly("https://grafana.furchert.ch");
    }

    @Test
    void loadsScopes() {
        assertThat(props.getClients().get(0).getScopes())
            .containsExactlyInAnyOrder("openid", "profile", "email");
    }
}
