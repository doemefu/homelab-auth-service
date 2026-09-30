package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.config.OidcClientProperties;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gate G4 of docs/080 §4.5 (#107): every existing client keeps its registration settings, token shape
 * and login behaviour. Real filter chain, production decoder, really signed tokens (no {@code jwt()},
 * no mocked decoder).
 */
class ExistingClientsUnchangedGateTest extends AbstractIntegrationTest {

    private static final String FC = "furchert-ch";
    private static final String FC_SECRET = "furchert-ch-secret";
    private static final String FC_CALLBACK = "https://furchert.test.local/api/auth/callback/furchert-ch";

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    JWKSource<SecurityContext> jwkSource;

    private AuthCodeFlow flow;

    @BeforeEach
    void setUp() {
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("testuser", "password123", Role.USER);
    }

    @Test
    void existingClientRowsKeepTheirSettings(@Autowired RegisteredClientRepository repo) {
        for (String id : List.of("test-client", "homeassistant", "device-service", "n8n", "litellm", "furchert-ch")) {
            RegisteredClient c = repo.findByClientId(id);
            assertThat(c.getClientAuthenticationMethods()).as(id).containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            assertThat(c.getClientSettings().isRequireAuthorizationConsent()).as(id).isFalse();
            assertThat(c.getTokenSettings().isReuseRefreshTokens()).as(id).isTrue();
            assertThat(c.getTokenSettings().getAccessTokenTimeToLive()).as(id).isEqualTo(Duration.ofMinutes(15));
            assertThat(c.getClientSettings().getSettings()).as(id)
                    .doesNotContainKey(OidcClientProperties.AUDIENCE_BOUND_SETTING);   // marker: hub only
        }
    }

    @Test
    void existingServiceTokenStillAcceptedOnAdminApi() throws Exception {
        // A real client_credentials token through the real filter chain, as device-service uses the
        // device-client admin API.
        String token = flow.json(mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "client_credentials").param("scope", "clients:admin")
                        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                                "device-service:device-service-secret".getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isOk()).andReturn()).get("access_token").asString();
        mockMvc.perform(get("/api/v1/clients").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void furchertChUserTokenKeepsRoleAndIsAcceptedByTheAdminApi() throws Exception {
        // Full furchert-ch auth-code flow with client_secret_basic and a resource parameter (ignored for this client).
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(FC, FC_CALLBACK, "openid profile email",
                "https://anything.example"), "testuser", "password123", p);
        String code = AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code");
        assertThat(code).isNotBlank();
        JsonNode body = flow.json(flow.exchangeBasic(FC, FC_SECRET, code, FC_CALLBACK, p, "https://anything.example")
                .andExpect(status().isOk()).andExpect(jsonPath("$.id_token").exists()).andReturn());
        String access = body.get("access_token").asString();
        Map<String, Object> h = AuthCodeFlow.header(access);
        Map<String, Object> c = AuthCodeFlow.payload(access);
        assertThat(h.get("typ")).isIn(null, "JWT");                 // never at+jwt
        assertThat(c).containsEntry("role", "USER").doesNotContainKey("client_id");
        assertThat(AuthCodeFlow.audiences(c)).containsExactly(FC);
        assertThat(((Number) c.get("exp")).longValue() - ((Number) c.get("iat")).longValue()).isEqualTo(900L);
        long testuserId = userRepository.findByUsername("testuser").orElseThrow().getId();
        mockMvc.perform(get("/api/v1/users/{id}", testuserId).header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        // Refresh with Basic: works, and the refresh token is not rotated (reuse = true).
        String refresh = body.get("refresh_token").asString();
        JsonNode refreshed = flow.json(mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token").param("refresh_token", refresh)
                        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                                (FC + ":" + FC_SECRET).getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isOk()).andReturn());
        if (refreshed.has("refresh_token")) {
            assertThat(refreshed.get("refresh_token").asString()).isEqualTo(refresh);
        }
    }

    @Test
    void existingClientStillRejectsClientSecretPost() throws Exception {
        mockMvc.perform(post("/oauth2/token").param("grant_type", "client_credentials").param("scope", "netmon:read")
                        .param("client_id", FC).param("client_secret", FC_SECRET))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void existingClientStillRejectsUnregisteredRedirectUri() throws Exception {
        MvcResult r = flow.authorizeAnonymous(
                new AuthCodeFlow.Req("test-client", "https://evil.test/cb", "openid", null), AuthCodeFlow.pkce());
        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(r.getResponse().getRedirectedUrl()).isNull();
    }

    @Test
    void existingClientLoginShowsNoConsentPage() throws Exception {
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req("test-client", "https://app.test.local/callback",
                "openid profile email", null), "testuser", "password123", AuthCodeFlow.pkce());
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code")).isNotBlank();
    }

    @Test
    void existingClientsNeverWriteConsentRows() throws Exception {
        // Consent storage is general, but only clients with consent enabled write rows.
        flow.authorizeAs(new AuthCodeFlow.Req("test-client", "https://app.test.local/callback",
                "openid profile email", null), "testuser", "password123", AuthCodeFlow.pkce());
        flow.authorizeAs(new AuthCodeFlow.Req(FC, FC_CALLBACK, "openid profile email", null),
                "testuser", "password123", AuthCodeFlow.pkce());
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM oauth2_authorization_consent c
                JOIN oauth2_registered_client r ON r.id = c.registered_client_id
                WHERE r.client_id <> 'claude-mcp-hub'""", Integer.class)).isZero();
    }
}
