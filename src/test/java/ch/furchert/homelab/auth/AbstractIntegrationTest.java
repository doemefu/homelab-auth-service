package ch.furchert.homelab.auth;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

@SpringBootTest
@AutoConfigureMockMvc
public abstract class AbstractIntegrationTest {

    // Static initializer keeps the container alive for the entire JVM lifetime.
    // Do NOT use @Testcontainers + @Container here: JUnit 5's AfterAllCallback
    // stops @Container static fields after each concrete subclass finishes, which
    // kills the container before the next integration test class can connect.
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

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
    }
}
