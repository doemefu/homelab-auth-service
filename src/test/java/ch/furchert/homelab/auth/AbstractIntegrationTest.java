package ch.furchert.homelab.auth;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest
@AutoConfigureMockMvc
public abstract class AbstractIntegrationTest {

    // Static initializer keeps the container alive for the entire JVM lifetime.
    // Do NOT use @Testcontainers + @Container here: JUnit 5's AfterAllCallback
    // stops @Container static fields after each concrete subclass finishes, which
    // kills the container before the next integration test class can connect.
    static final PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17-alpine");

    static {
        postgres.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("app.oidc.issuer", () -> "https://auth.test.local");

        // clients[0]: replaces grafana — primary test client used by OidcFlowIntegrationTest.
        registry.add("app.oidc.clients[0].client-id", () -> "test-client");
        registry.add("app.oidc.clients[0].client-secret", () -> "{noop}test-secret");
        registry.add("app.oidc.clients[0].redirect-uris[0]", () -> "https://app.test.local/callback");
        registry.add("app.oidc.clients[0].post-logout-redirect-uris[0]", () -> "https://app.test.local");
        registry.add("app.oidc.clients[0].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[0].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[0].scopes[2]", () -> "email");

        // Override remaining SSO clients so that their ${*_CLIENT_SECRET} placeholders
        // in application.yaml are never evaluated without env vars present in CI.
        registry.add("app.oidc.clients[1].client-id", () -> "homeassistant");
        registry.add("app.oidc.clients[1].client-secret", () -> "{noop}test-secret-ha");
        registry.add("app.oidc.clients[1].redirect-uris[0]", () -> "https://ha.test.local/callback");
        registry.add("app.oidc.clients[1].post-logout-redirect-uris[0]", () -> "https://ha.test.local");
        registry.add("app.oidc.clients[1].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[1].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[1].scopes[2]", () -> "email");

        // clients[2]: device-service — kept multi-grant so S2S tests can exercise
        // client_credentials with the clients:admin scope.
        registry.add("app.oidc.clients[2].client-id", () -> "device-service");
        registry.add("app.oidc.clients[2].client-secret", () -> "{noop}device-service-secret");
        registry.add("app.oidc.clients[2].redirect-uris[0]", () -> "https://device.test.local/callback");
        registry.add("app.oidc.clients[2].post-logout-redirect-uris[0]", () -> "https://device.test.local");
        registry.add("app.oidc.clients[2].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[2].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[2].scopes[2]", () -> "email");
        registry.add("app.oidc.clients[2].scopes[3]", () -> "clients:admin");
        registry.add("app.oidc.clients[2].grant-types[0]", () -> "authorization_code");
        registry.add("app.oidc.clients[2].grant-types[1]", () -> "refresh_token");
        registry.add("app.oidc.clients[2].grant-types[2]", () -> "client_credentials");

        registry.add("app.oidc.clients[3].client-id", () -> "n8n");
        registry.add("app.oidc.clients[3].client-secret", () -> "{noop}test-secret-n8n");
        registry.add("app.oidc.clients[3].redirect-uris[0]", () -> "https://n8n.test.local/callback");
        registry.add("app.oidc.clients[3].post-logout-redirect-uris[0]", () -> "https://n8n.test.local");
        registry.add("app.oidc.clients[3].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[3].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[3].scopes[2]", () -> "email");

        registry.add("app.oidc.clients[4].client-id", () -> "litellm");
        registry.add("app.oidc.clients[4].client-secret", () -> "{noop}test-secret-litellm");
        registry.add("app.oidc.clients[4].redirect-uris[0]", () -> "https://ai.test.local/callback");
        registry.add("app.oidc.clients[4].post-logout-redirect-uris[0]", () -> "https://ai.test.local");
        registry.add("app.oidc.clients[4].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[4].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[4].scopes[2]", () -> "email");

        // clients[5]: furchert-ch — mirrors application.yaml (auth_code for dashboard SSO
        // + client_credentials with netmon:read for data-service, docs/060 §7.5).
        registry.add("app.oidc.clients[5].client-id", () -> "furchert-ch");
        registry.add("app.oidc.clients[5].client-secret", () -> "{noop}furchert-ch-secret");
        registry.add("app.oidc.clients[5].redirect-uris[0]", () -> "https://furchert.test.local/api/auth/callback/furchert-ch");
        registry.add("app.oidc.clients[5].post-logout-redirect-uris[0]", () -> "https://furchert.test.local");
        registry.add("app.oidc.clients[5].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[5].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[5].scopes[2]", () -> "email");
        registry.add("app.oidc.clients[5].scopes[3]", () -> "netmon:read");
        registry.add("app.oidc.clients[5].grant-types[0]", () -> "authorization_code");
        registry.add("app.oidc.clients[5].grant-types[1]", () -> "refresh_token");
        registry.add("app.oidc.clients[5].grant-types[2]", () -> "client_credentials");

        // clients[6]: claude-mcp-hub — mirrors application.yaml (docs/080 §4.1, #107). The secret is a
        // throwaway value hashed here in the production format ({bcrypt}$2y$10$…, as htpasswd produces),
        // so every hub token request in the gate tests also proves that format is accepted.
        registry.add("app.oidc.clients[6].client-id", () -> "claude-mcp-hub");
        registry.add("app.oidc.clients[6].client-secret", () -> HUB_SECRET_HASH);
        registry.add("app.oidc.clients[6].redirect-uris[0]", () -> "https://claude.ai/api/mcp/auth_callback");
        registry.add("app.oidc.clients[6].redirect-uris[1]", () -> "https://claude.com/api/mcp/auth_callback");
        registry.add("app.oidc.clients[6].scopes[0]", () -> "mail:read");
        registry.add("app.oidc.clients[6].scopes[1]", () -> "calendar:read");
        registry.add("app.oidc.clients[6].grant-types[0]", () -> "authorization_code");
        registry.add("app.oidc.clients[6].grant-types[1]", () -> "refresh_token");
        registry.add("app.oidc.clients[6].client-authentication-methods[0]", () -> "client_secret_basic");
        registry.add("app.oidc.clients[6].client-authentication-methods[1]", () -> "client_secret_post");
        registry.add("app.oidc.clients[6].reuse-refresh-tokens", () -> "false");
        registry.add("app.oidc.clients[6].require-authorization-consent", () -> "true");
        registry.add("app.oidc.clients[6].access-token-time-to-live", () -> "10m");
        registry.add("app.oidc.clients[6].access-token-audience", () -> "https://mcp.furchert.ch/mcp");
        registry.add("app.oidc.clients[6].allowed-resources[0]", () -> "https://mcp.furchert.ch/mcp");
        registry.add("app.oidc.clients[6].restrict-to-allowed-users", () -> "true");
        registry.add("app.oidc.clients[6].allowed-users", () -> "hubowner, hubadmin");
    }

    // Throwaway test secret "hub-secret"; cost 10 and revision $2y$ like the production value.
    static final String HUB_SECRET_HASH = "{bcrypt}" + new BCryptPasswordEncoder(
            BCryptPasswordEncoder.BCryptVersion.$2Y, 10).encode("hub-secret");
}
