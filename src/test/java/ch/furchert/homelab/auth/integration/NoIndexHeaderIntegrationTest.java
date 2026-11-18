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
    void allEndpointsCarryExactlyOneNoindexHeader() {
        String[][] cases = {
                {"/login", "200"}, {"/userinfo", "302"}, {"/.well-known/openid-configuration", "200"},
                {"/oauth2/jwks", "200"}, {"/actuator/health", "200"}, {"/api/v1/users", "401"},
                {"/swagger-ui.html", "302"}, {"/does-not-exist", "403"}};
        for (String[] c : cases) {
            var res = client().get().uri(c[0]).retrieve().toBodilessEntity();
            assertThat(res.getStatusCode().value()).as(c[0]).isEqualTo(Integer.parseInt(c[1]));
            assertThat(res.getHeaders().get("X-Robots-Tag")).as(c[0]).containsExactly("noindex, nofollow");
        }
    }
}
