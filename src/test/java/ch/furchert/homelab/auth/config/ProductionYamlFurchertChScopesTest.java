package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Checks the real {@code src/main/resources/application.yaml} (the test classpath shadows it):
 * the furchert-ch client lists the web-analytics scopes next to its existing ones
 * (docs/100-web-analytics.md §11, #142), with unchanged grant types.
 */
class ProductionYamlFurchertChScopesTest {

    @Test
    void furchertChListsBothAnalyticsScopes() throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(
                new MapPropertySource("fake-env", Map.of("FURCHERT_CH_CLIENT_SECRET", "{noop}x")));
        List<PropertySource<?>> yaml = new YamlPropertySourceLoader()
                .load("main-application-yaml", new FileSystemResource("src/main/resources/application.yaml"));
        yaml.forEach(environment.getPropertySources()::addLast);

        OidcClientProperties oidc = Binder.get(environment).bind("app.oidc", OidcClientProperties.class).get();
        OidcClientProperties.ClientDefinition fc = oidc.getClients().stream()
                .filter(c -> "furchert-ch".equals(c.getClientId())).findFirst().orElseThrow();

        assertThat(fc.getScopes()).containsExactlyInAnyOrder(
                "openid", "profile", "email", "netmon:read", "analytics:write", "analytics:read");
        assertThat(fc.getGrantTypes()).containsExactlyInAnyOrder(
                "authorization_code", "refresh_token", "client_credentials");
    }
}
