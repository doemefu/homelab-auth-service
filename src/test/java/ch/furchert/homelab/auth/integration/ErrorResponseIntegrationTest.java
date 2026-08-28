package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;

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

    @Autowired
    JWKSource<SecurityContext> jwkSource;

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
                // Treat 4xx/5xx as "not an error" so retrieve() never throws for the error
                // responses under test — we assert on the raw ResponseEntity instead. 3xx
                // redirects are excluded from the predicate on purpose: RestClient's default
                // status handling never throws for 3xx anyway, so widening the match to "any
                // status" (including 2xx) would silently swallow future assertions on success
                // responses too.
                .defaultStatusHandler(HttpStatusCode::isError, (req, res) -> { })
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
    void logoutWithBogusIdTokenHintReturnsRenderedErrorPage() {
        // A hint that is not a validly-signed JWT can never prove it came from this IdP,
        // so the handler must fall back to the standard 400 error page rather than ending
        // the caller's session — otherwise "id_token_hint=bogus" would be a cross-site
        // forced-logout link (Copilot round-3 finding).
        ResponseEntity<String> response = client().get()
                .uri("/connect/logout?id_token_hint=bogus&post_logout_redirect_uri=https%3A%2F%2Ffurchert.ch")
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString()).startsWith(MediaType.TEXT_HTML_VALUE);
        assertThat(response.getBody()).isNotBlank();
    }

    @Test
    void logoutWithStaleButGenuineIdTokenHintRedirectsToLoginLogout() {
        // A token that is genuinely signed by this server — even though it is long expired
        // and its authorization row has been purged, so Spring Authorization Server's own
        // lookup fails with invalid_token — is proof of a legitimate former RP session. The
        // handler must still end the local session in that case (unlike the bogus-hint case
        // above), since SAS cannot resolve it.
        Instant issuedAt = Instant.now().minusSeconds(8 * 24 * 60 * 60);
        Instant expiresAt = issuedAt.plusSeconds(30 * 60);

        JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://auth.test.local")
                .subject("stale-user")
                .audience(List.of("furchert-ch"))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id("test")
                .build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        ResponseEntity<String> response = client().get()
                .uri("/connect/logout?id_token_hint=" + token + "&post_logout_redirect_uri=https%3A%2F%2Ffurchert.ch")
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
