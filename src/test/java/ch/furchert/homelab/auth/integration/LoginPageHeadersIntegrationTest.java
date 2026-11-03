package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * #106 item 2 over real HTTP (MockMvc ignores the servlet container's cookie settings): the login page
 * carries the CSP and the session cookie is Secure, HttpOnly and SameSite=Lax; other endpoints carry no
 * CSP, so the scope cannot widen unnoticed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LoginPageHeadersIntegrationTest extends AbstractIntegrationTest {

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
    void loginPageHasTheCspAndASecureSameSiteSessionCookie() {
        ResponseEntity<String> page = client().get().uri("/login").retrieve().toEntity(String.class);

        assertThat(page.getStatusCode().value()).isEqualTo(200);
        String csp = page.getHeaders().getFirst("Content-Security-Policy");
        assertThat(csp).contains("default-src 'none'").contains("style-src 'self' 'unsafe-inline'")
                .contains("frame-ancestors 'none'").doesNotContain("form-action").doesNotContain("script-src");
        List<String> cookies = page.getHeaders().getOrEmpty(HttpHeaders.SET_COOKIE);
        assertThat(cookies).anySatisfy(c -> assertThat(c).startsWith("JSESSIONID=")
                .contains("Secure").contains("HttpOnly").contains("SameSite=Lax"));
    }

    @Test
    void loginErrorPageAndHeadAlsoCarryTheCsp() {
        assertThat(client().get().uri("/login?error").retrieve().toEntity(String.class).getHeaders()
                .getFirst("Content-Security-Policy")).contains("default-src 'none'");
        assertThat(client().head().uri("/login").retrieve().toBodilessEntity().getHeaders()
                .getFirst("Content-Security-Policy")).contains("default-src 'none'");
    }

    @Test
    void otherEndpointsCarryNoCsp() {
        assertThat(client().get().uri("/actuator/health").retrieve().toEntity(String.class).getHeaders()
                .getFirst("Content-Security-Policy")).isNull();
        assertThat(client().get().uri("/oauth2/authorize?response_type=code&client_id=test-client")
                .retrieve().toEntity(String.class).getHeaders().getFirst("Content-Security-Policy")).isNull();
    }
}
