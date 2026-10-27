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
 * club-assistant D67: the claude-club-mcp client is optional. Checked against the real
 * src/main/resources/application.yaml (the test classpath shadows it) and k8s/deployment.yaml.
 * If this test fails because the entry was removed or renamed: remove the client first as described
 * in DEPLOYMENT.md ("Remove or rename the claude-club-mcp client").
 */
class ProductionYamlClaudeClubMcpClientTest {

    private static OidcClientProperties.ClientDefinition club(Map<String, Object> env) throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("fake-env", env));
        List<PropertySource<?>> yaml = new YamlPropertySourceLoader()
                .load("main-application-yaml", new FileSystemResource("src/main/resources/application.yaml"));
        yaml.forEach(environment.getPropertySources()::addLast);
        OidcClientProperties oidc = Binder.get(environment).bind("app.oidc", OidcClientProperties.class).get();
        return oidc.findClient("claude-club-mcp").orElseThrow();
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
        OidcClientProperties.ClientDefinition club = club(existingSecrets());
        assertThat(club.getClientSecret()).isBlank();          // seeder skips it
        assertThat(club.isRestrictToAllowedUsers()).isTrue();
        assertThat(club.getAllowedUsers()).isEmpty();          // fail-closed
    }

    @Test
    void registrationMatchesContract() throws IOException {
        Map<String, Object> env = existingSecrets();
        env.put("CLAUDE_CLUB_MCP_CLIENT_SECRET", "{noop}x");
        env.put("CLAUDE_CLUB_MCP_ALLOWED_USERS", " owner-a , owner-b ");
        OidcClientProperties.ClientDefinition club = club(env);

        assertThat(club.getRedirectUris()).containsExactly(
                "https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback");
        assertThat(club.getPostLogoutRedirectUris()).isEmpty();
        assertThat(club.getScopes()).containsExactly("club:read");
        assertThat(club.getGrantTypes()).containsExactly("authorization_code", "refresh_token");
        assertThat(club.getClientAuthenticationMethods())
                .containsExactlyInAnyOrder("client_secret_basic", "client_secret_post");
        assertThat(club.isReuseRefreshTokens()).isFalse();
        assertThat(club.isRequireAuthorizationConsent()).isTrue();
        assertThat(club.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(10));
        assertThat(club.getAccessTokenAudience()).isEqualTo("https://club-mcp.furchert.ch/mcp");
        assertThat(club.getAllowedResources()).containsExactly("https://club-mcp.furchert.ch/mcp");
        assertThat(club.getAllowedUsers()).containsExactly("owner-a", "owner-b");
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
                "CLAUDE_CLUB_MCP_CLIENT_SECRET", "claude-club-mcp-client-secret",
                "CLAUDE_CLUB_MCP_ALLOWED_USERS", "claude-club-mcp-allowed-users");
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
