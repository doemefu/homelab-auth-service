package ch.furchert.homelab.auth;

import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
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
        registry.add("app.oidc.clients[0].client-id", () -> "test-client");
        registry.add("app.oidc.clients[0].client-secret", () -> "{noop}test-secret");
        registry.add("app.oidc.clients[0].redirect-uris[0]", () -> "https://app.test.local/callback");
        registry.add("app.oidc.clients[0].post-logout-redirect-uris[0]", () -> "https://app.test.local");
        registry.add("app.oidc.clients[0].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[0].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[0].scopes[2]", () -> "email");
        // Override clients[1] so that ${HA_CLIENT_SECRET} and ${GRAFANA_CLIENT_SECRET}
        // in application.yaml are never evaluated without the env vars present in CI.
        registry.add("app.oidc.clients[1].client-id", () -> "homeassistant");
        registry.add("app.oidc.clients[1].client-secret", () -> "{noop}test-secret-ha");
        registry.add("app.oidc.clients[1].redirect-uris[0]", () -> "https://ha.test.local/callback");
        registry.add("app.oidc.clients[1].post-logout-redirect-uris[0]", () -> "https://ha.test.local");
        registry.add("app.oidc.clients[1].scopes[0]", () -> "openid");
        registry.add("app.oidc.clients[1].scopes[1]", () -> "profile");
        registry.add("app.oidc.clients[1].scopes[2]", () -> "email");
    }
}
