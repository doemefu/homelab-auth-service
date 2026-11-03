package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * #106: the real {@code src/main/resources/application.yaml} (the test classpath shadows it) sets the
 * session-cookie flags and the default kid; LoginPageHeadersIntegrationTest proves Tomcat sends them.
 */
class ProductionYamlSessionCookieTest {

    @Test
    void productionYamlSetsTheSessionCookieFlagsAndTheDefaultKid() throws IOException {
        StandardEnvironment env = new StandardEnvironment();
        new YamlPropertySourceLoader()
                .load("main-application-yaml", new FileSystemResource("src/main/resources/application.yaml"))
                .forEach(env.getPropertySources()::addLast);

        assertThat(env.getProperty("server.servlet.session.cookie.secure")).isEqualTo("true");
        assertThat(env.getProperty("server.servlet.session.cookie.http-only")).isEqualTo("true");
        assertThat(env.getProperty("server.servlet.session.cookie.same-site")).isEqualTo("lax");
        assertThat(env.getProperty("app.jwt.key-id")).isEqualTo("auth-service-v1");
    }
}
