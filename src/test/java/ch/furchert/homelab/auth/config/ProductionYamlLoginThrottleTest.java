package ch.furchert.homelab.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

import java.io.IOException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** #104: the production defaults in the real {@code src/main/resources/application.yaml} bind as documented. */
class ProductionYamlLoginThrottleTest {

    @Test
    void productionDefaultsBind() throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        new YamlPropertySourceLoader()
                .load("main-application-yaml", new FileSystemResource("src/main/resources/application.yaml"))
                .forEach(environment.getPropertySources()::addLast);

        LoginThrottleProperties p = Binder.get(environment)
                .bind("app.login-throttle", LoginThrottleProperties.class).get();

        assertThat(p.isEnabled()).isTrue();
        assertThat(p.getUser().getMaxFailures()).isEqualTo(10);
        assertThat(p.getUser().getWindow()).isEqualTo(Duration.ofMinutes(15));
        assertThat(p.getUser().getLockDuration()).isEqualTo(Duration.ofMinutes(5));
        assertThat(p.getIp().getMaxFailures()).isEqualTo(20);
        assertThat(p.getIp().getLockDuration()).isEqualTo(Duration.ofMinutes(15));
        assertThat(p.getClient().getMaxFailures()).isEqualTo(10);
        assertThat(p.getClient().getWindow()).isEqualTo(Duration.ofMinutes(5));
        assertThat(p.getClient().getLockDuration()).isEqualTo(Duration.ofMinutes(5));
        assertThat(p.getKnownGoodTtl()).isEqualTo(Duration.ofDays(30));
        assertThat(p.getMaxEntries()).isEqualTo(30_000);
    }
}
