package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/080 §4.1 (#107): the claude-mcp-hub client is optional. Checked against the real
 * src/main/resources/application.yaml (the test classpath shadows it) and k8s/deployment.yaml.
 * If this test fails because the entry was removed or renamed: remove the client first as described
 * in DEPLOYMENT.md ("Remove or rename the claude-mcp-hub client").
 */
class ProductionYamlClaudeMcpHubClientTest {

    private static OidcClientProperties.ClientDefinition hub(Map<String, Object> env) throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("fake-env", env));
        List<PropertySource<?>> yaml = new YamlPropertySourceLoader()
                .load("main-application-yaml", new FileSystemResource("src/main/resources/application.yaml"));
        yaml.forEach(environment.getPropertySources()::addLast);
        OidcClientProperties oidc = Binder.get(environment).bind("app.oidc", OidcClientProperties.class).get();
        return oidc.findClient("claude-mcp-hub").orElseThrow();
    }

    private static Map<String, Object> existingSecrets() {
        Map<String, Object> env = new HashMap<>();
        for (String name : List.of("GRAFANA", "HA", "DEVICE_SERVICE", "N8N", "LITELLM", "FURCHERT_CH")) {
            env.put(name + "_CLIENT_SECRET", "{noop}x");
        }
        return env;
    }

    @Test
    void envAbsent_clientIsInertAndFailClosed() throws IOException {
        OidcClientProperties.ClientDefinition hub = hub(existingSecrets());
        assertThat(hub.getClientSecret()).isBlank();          // seeder skips it
        assertThat(hub.isRestrictToAllowedUsers()).isTrue();
        assertThat(hub.getAllowedUsers()).isEmpty();          // fail-closed
    }

    @Test
    void registrationMatchesSpec080() throws IOException {
        Map<String, Object> env = existingSecrets();
        env.put("CLAUDE_MCP_HUB_CLIENT_SECRET", "{noop}x");
        env.put("CLAUDE_MCP_HUB_ALLOWED_USERS", " owner-a , owner-b ");
        OidcClientProperties.ClientDefinition hub = hub(env);

        assertThat(hub.getRedirectUris()).containsExactly(
                "https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback");
        assertThat(hub.getPostLogoutRedirectUris()).isEmpty();
        assertThat(hub.getScopes()).containsExactly("mail:read", "calendar:read");
        assertThat(hub.getGrantTypes()).containsExactly("authorization_code", "refresh_token");
        assertThat(hub.getClientAuthenticationMethods())
                .containsExactlyInAnyOrder("client_secret_basic", "client_secret_post");
        assertThat(hub.isReuseRefreshTokens()).isFalse();
        assertThat(hub.isRequireAuthorizationConsent()).isTrue();
        assertThat(hub.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(10));
        assertThat(hub.getAccessTokenAudience()).isEqualTo("https://mcp.furchert.ch/mcp");
        assertThat(hub.getAllowedResources()).containsExactly("https://mcp.furchert.ch/mcp");
        assertThat(hub.getAllowedUsers()).containsExactly("owner-a", "owner-b");
    }

    @Test
    void otherClientsKeepDefaults() throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("fake-env", existingSecrets()));
        new YamlPropertySourceLoader()
                .load("y", new FileSystemResource("src/main/resources/application.yaml"))
                .forEach(environment.getPropertySources()::addLast);
        OidcClientProperties oidc = Binder.get(environment).bind("app.oidc", OidcClientProperties.class).get();
        oidc.getClients().stream().filter(c -> !"claude-mcp-hub".equals(c.getClientId())).forEach(c -> {
            assertThat(c.getClientAuthenticationMethods()).as(c.getClientId()).containsExactly("client_secret_basic");
            assertThat(c.isRequireAuthorizationConsent()).as(c.getClientId()).isFalse();
            assertThat(c.isReuseRefreshTokens()).as(c.getClientId()).isTrue();
            assertThat(c.getAccessTokenTimeToLive()).as(c.getClientId()).isNull();
            assertThat(c.getAccessTokenAudience()).as(c.getClientId()).isNull();
            assertThat(c.getAllowedResources()).as(c.getClientId()).isEmpty();
            assertThat(c.isRestrictToAllowedUsers()).as(c.getClientId()).isFalse();
        });
    }

    @Test
    @SuppressWarnings("unchecked")
    void deploymentWiresBothEnvVarsAsOptionalSecretRefs() throws IOException {
        Map<String, Object> deployment;
        try (InputStream in = Files.newInputStream(Path.of("k8s/deployment.yaml"))) {
            deployment = new Yaml().load(in);
        }
        Map<String, Object> spec = (Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>)
                deployment.get("spec")).get("template")).get("spec");
        List<Map<String, Object>> env = (List<Map<String, Object>>)
                ((List<Map<String, Object>>) spec.get("containers")).getFirst().get("env");
        Map<String, String> expectedKeys = Map.of(
                "CLAUDE_MCP_HUB_CLIENT_SECRET", "claude-mcp-hub-client-secret",
                "CLAUDE_MCP_HUB_ALLOWED_USERS", "claude-mcp-hub-allowed-users");
        expectedKeys.forEach((name, key) -> {
            Map<String, Object> ref = env.stream().filter(e -> name.equals(e.get("name"))).findFirst()
                    .map(e -> (Map<String, Object>) ((Map<String, Object>) e.get("valueFrom")).get("secretKeyRef"))
                    .orElseThrow(() -> new AssertionError(name + " missing"));
            assertThat(ref).containsEntry("name", "homelab-auth-secrets")
                    .containsEntry("key", key)
                    .containsEntry("optional", true);
        });
    }
}
