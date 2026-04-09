package ch.furchert.homelab.auth;

import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
public abstract class AbstractIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");

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
    }
}
