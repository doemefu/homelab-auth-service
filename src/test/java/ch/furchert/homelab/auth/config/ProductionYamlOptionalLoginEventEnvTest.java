package ch.furchert.homelab.auth.config;

import ch.furchert.homelab.auth.service.LoginEventFeature;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * NM-4 overnight hard rule, checked against the real {@code src/main/resources/application.yaml}
 * (the test classpath shadows it): the two new env vars must be optional. With every existing
 * client secret present but {@code DATA_SERVICE_CLIENT_SECRET} and {@code LOGIN_EVENT_HMAC_KEY}
 * absent, binding succeeds, the data-service secret resolves to blank (the seeder skips it) and the
 * feature is disabled.
 */
class ProductionYamlOptionalLoginEventEnvTest {

    private static StandardEnvironment environment(Map<String, Object> env) throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("fake-env", env));
        List<PropertySource<?>> yaml = new YamlPropertySourceLoader()
                .load("main-application-yaml", new FileSystemResource("src/main/resources/application.yaml"));
        yaml.forEach(environment.getPropertySources()::addLast);
        return environment;
    }

    private static Map<String, Object> existingSecrets() {
        Map<String, Object> env = new HashMap<>();
        for (String name : List.of("GRAFANA", "HA", "DEVICE_SERVICE", "N8N", "LITELLM", "FURCHERT_CH")) {
            env.put(name + "_CLIENT_SECRET", "{noop}x");
        }
        return env;
    }

    @Test
    void newEnvVarsAbsent_bindsAndDisablesFeature() throws IOException {
        Binder binder = Binder.get(environment(existingSecrets()));

        OidcClientProperties oidc = binder.bind("app.oidc", OidcClientProperties.class).get();
        LoginEventProperties loginEvents = binder.bind("app.login-events", LoginEventProperties.class)
                .orElseGet(LoginEventProperties::new);

        OidcClientProperties.ClientDefinition ds = oidc.getClients().stream()
                .filter(c -> "data-service".equals(c.getClientId())).findFirst().orElseThrow();
        assertThat(ds.getClientSecret()).isBlank();
        assertThat(ds.getRedirectUris()).isEmpty();
        assertThat(ds.getScopes()).containsExactly("login-events:read");
        assertThat(ds.getGrantTypes()).containsExactly("client_credentials");
        assertThat(loginEvents.getHmacKey()).isBlank();
        assertThat(new LoginEventFeature(loginEvents, oidc).isEnabled()).isFalse();
    }

    @Test
    void newEnvVarsPresent_enablesFeature() throws IOException {
        Map<String, Object> env = existingSecrets();
        env.put("DATA_SERVICE_CLIENT_SECRET", "{noop}ds");
        env.put("LOGIN_EVENT_HMAC_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        Binder binder = Binder.get(environment(env));

        OidcClientProperties oidc = binder.bind("app.oidc", OidcClientProperties.class).get();
        LoginEventProperties loginEvents = binder.bind("app.login-events", LoginEventProperties.class).get();

        assertThat(new LoginEventFeature(loginEvents, oidc).isEnabled()).isTrue();
        assertThat(loginEvents.getTtl()).hasHours(72);
    }
}
