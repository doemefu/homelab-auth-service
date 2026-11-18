package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;

/** #168: every response carries {@code X-Robots-Tag: noindex, nofollow}, whichever chain serves it. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class NoIndexHeaderIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    int port;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .requestFactory(new JdkClientHttpRequestFactory(HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_1_1)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build()))
                .defaultStatusHandler(HttpStatusCode::isError, (req, res) -> { })
                .build();
    }

    @Test
    void allEndpointsCarryNoindex() {
        for (String path : new String[] {"/login", "/userinfo", "/.well-known/openid-configuration",
                "/oauth2/jwks", "/actuator/health", "/api/v1/users", "/does-not-exist"}) {
            assertThat(client().get().uri(path).retrieve().toBodilessEntity().getHeaders()
                    .getFirst("X-Robots-Tag")).as(path).isEqualTo("noindex, nofollow");
        }
    }
}
