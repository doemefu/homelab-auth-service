package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that error responses (Spring Boot's ERROR-dispatch forward to {@code /error})
 * and RP-initiated OIDC logout produce a real, non-empty body with a Content-Type header,
 * instead of the empty 403 that made browsers download error responses (#77).
 * <p>
 * Uses a real embedded server ({@code RANDOM_PORT}) rather than MockMvc: MockMvc's
 * {@code DispatcherServlet} mock never performs the container-level ERROR-dispatch
 * forward that Boot's error-page mechanism triggers on {@code sendError()}, so it
 * cannot observe the bug this test guards against.
 * <p>
 * Note on {@code /does-not-exist}: the catch-all chain's {@code denyAll()} intercepts
 * any path not matched by an earlier, more specific chain <em>before</em> Spring MVC's
 * {@code DispatcherServlet} ever runs — so an unmapped path never reaches Spring MVC's
 * own "no handler found" 404 logic and is denied with 403 instead. That is pre-existing,
 * intentional behavior (unmapped paths are refused, not distinguished from mapped-but-
 * forbidden ones); the bug under test is the empty body/missing Content-Type on that
 * 403, not the status code itself.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorResponseIntegrationTest extends AbstractIntegrationTest {

    @LocalServerPort
    int port;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .requestFactory(new JdkClientHttpRequestFactory(
                        HttpClient.newBuilder()
                                // Force HTTP/1.1: the JDK client's speculative h2c upgrade attempt
                                // against a plain HTTP/1.1-only embedded Tomcat produces unrelated
                                // "Error parsing HTTP request header" noise on a second connection.
                                .version(HttpClient.Version.HTTP_1_1)
                                .followRedirects(HttpClient.Redirect.NEVER)
                                .build()))
                // Treat every status as "not an error" so retrieve() never throws for 3xx/4xx —
                // we assert on the raw ResponseEntity instead.
                .defaultStatusHandler(status -> true, (req, res) -> { })
                .build();
    }

    @Test
    void unmatchedPathWithHtmlAcceptReturnsRenderedHtmlErrorBody() {
        ResponseEntity<String> response = client().get()
                .uri("/does-not-exist")
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString()).startsWith(MediaType.TEXT_HTML_VALUE);
        assertThat(response.getBody()).isNotBlank();
    }

    @Test
    void unmatchedPathWithJsonAcceptReturnsJsonErrorBody() {
        ResponseEntity<String> response = client().get()
                .uri("/does-not-exist")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
        assertThat(response.getBody()).isNotBlank();
    }

    @Test
    void unmatchedPathWithWildcardAcceptReturnsNonEmptyContentType() {
        ResponseEntity<String> response = client().get()
                .uri("/does-not-exist")
                .header(HttpHeaders.ACCEPT, MediaType.ALL_VALUE)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        // Observed: Spring's content negotiation resolves a bare "Accept: */*" (what a
        // plain `curl` sends by default) to BasicErrorController's unrestricted JSON
        // handler, not the text/html-producing one — the opposite of what a browser
        // navigation (explicit "Accept: text/html, ...") gets. Asserted concretely here
        // since this documents actual negotiation behavior, not just "some content type".
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
        assertThat(response.getBody()).isNotBlank();
    }

    @Test
    void logoutWithUnresolvableIdTokenHintRedirectsToLoginLogout() {
        ResponseEntity<String> response = client().get()
                .uri("/connect/logout?id_token_hint=bogus&post_logout_redirect_uri=https%3A%2F%2Ffurchert.ch")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(302);
        String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
        assertThat(location).isNotNull();
        assertThat(location).endsWith("/login?logout");
    }

    @Test
    void loginPostWithoutCsrfTokenReturnsRenderedForbiddenBody() {
        ResponseEntity<String> response = client().post()
                .uri("/login")
                // A real browser's full-page form submission sends "Accept: text/html, ...".
                // Without an explicit Accept header, negotiation resolves to JSON (same as
                // the wildcard case above) — sending it here exercises the actual browser
                // download-a-blank-file scenario from #77.
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString()).startsWith(MediaType.TEXT_HTML_VALUE);
        assertThat(response.getBody()).isNotBlank();
    }

    @Test
    void unauthenticatedApiRequestReturnsUnauthorizedJsonBody() {
        ResponseEntity<String> response = client().get()
                .uri("/api/v1/users")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
        assertThat(response.getBody()).isNotBlank();
    }
}
