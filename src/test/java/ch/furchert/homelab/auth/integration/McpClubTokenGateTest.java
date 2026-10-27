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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.CLUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.CLUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.CLUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.CLUB_SECRET;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_CALLBACK;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gates for the second pre-registered MCP client {@code claude-club-mcp} (club-assistant D67): token shape,
 * cross-audience isolation against the hub client, admin-API rejection and an unchanged hub registration.
 * Real application context, production decoder, really signed tokens (no mocked decoder).
 */
class McpClubTokenGateTest extends AbstractIntegrationTest {

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
    @Autowired
    RegisteredClientRepository registeredClients;

    private AuthCodeFlow flow;

    @BeforeEach
    void setUp() {
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("clubowner", "password123", Role.USER);
        flow.createUser("hubowner", "password123", Role.USER);
    }

    @Test
    @SuppressWarnings("unchecked")
    void clubTokenHasTheClubShape() throws Exception {
        AuthCodeFlow.TokenPair t = flow.clubTokens("clubowner", "password123");
        Map<String, Object> h = AuthCodeFlow.header(t.accessToken());
        Map<String, Object> c = AuthCodeFlow.payload(t.accessToken());
        assertThat(h).containsEntry("typ", "at+jwt").containsEntry("alg", "RS256");
        assertThat(AuthCodeFlow.audiences(c)).containsExactly(CLUB_RESOURCE);
        assertThat(c).containsEntry("client_id", CLUB).containsEntry("sub", "clubowner")
                .doesNotContainKey("role").doesNotContainKey("device_id");
        assertThat((List<String>) c.get("scope")).containsExactly(CLUB_SCOPE);
        assertThat(((Number) c.get("exp")).longValue() - ((Number) c.get("iat")).longValue()).isEqualTo(600L);
    }

    @Test
    void clubRefreshRotatesAndKeepsTheShape() throws Exception {
        AuthCodeFlow.TokenPair first = flow.clubTokens("clubowner", "password123");
        JsonNode refreshed = flow.json(flow.refreshPost(CLUB, CLUB_SECRET, first.refreshToken(), CLUB_RESOURCE)
                .andExpect(status().isOk()).andExpect(jsonPath("$.id_token").doesNotExist()).andReturn());
        assertThat(refreshed.get("refresh_token").asString()).isNotEqualTo(first.refreshToken());
        Map<String, Object> c = AuthCodeFlow.payload(refreshed.get("access_token").asString());
        assertThat(AuthCodeFlow.audiences(c)).containsExactly(CLUB_RESOURCE);
        assertThat(c).containsEntry("client_id", CLUB).doesNotContainKey("role");
        flow.refreshPost(CLUB, CLUB_SECRET, first.refreshToken(), CLUB_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void hubAudienceWithTheClubClientIsInvalidTarget() throws Exception {
        // authorization endpoint
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(CLUB, HUB_CALLBACK, CLUB_SCOPE, HUB_RESOURCE),
                "clubowner", "password123", AuthCodeFlow.pkce());
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "error")).isEqualTo("invalid_target");
        // token endpoint (exchange) and refresh
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = flow.clubCode(new AuthCodeFlow.Req(CLUB, HUB_CALLBACK, CLUB_SCOPE, CLUB_RESOURCE),
                "clubowner", "password123", p);
        flow.exchangePost(CLUB, CLUB_SECRET, code, HUB_CALLBACK, p, HUB_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
        AuthCodeFlow.TokenPair t = flow.clubTokens("clubowner", "password123");
        flow.refreshPost(CLUB, CLUB_SECRET, t.refreshToken(), HUB_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
    }

    @Test
    void clubScopeCannotBeUsedWithTheHubClientAndViceVersa() throws Exception {
        MvcResult hubWithClubScope = flow.authorizeAs(new AuthCodeFlow.Req(HUB, HUB_CALLBACK, CLUB_SCOPE, HUB_RESOURCE),
                "hubowner", "password123", AuthCodeFlow.pkce());
        assertThat(AuthCodeFlow.param(hubWithClubScope.getResponse().getRedirectedUrl(), "error"))
                .isEqualTo("invalid_scope");
        MvcResult clubWithHubScope = flow.authorizeAs(new AuthCodeFlow.Req(CLUB, HUB_CALLBACK, HUB_SCOPE, CLUB_RESOURCE),
                "clubowner", "password123", AuthCodeFlow.pkce());
        assertThat(AuthCodeFlow.param(clubWithHubScope.getResponse().getRedirectedUrl(), "error"))
                .isEqualTo("invalid_scope");
    }

    @Test
    void userOutsideTheClubAllowlistIsRejected() throws Exception {
        // "hubowner" is allowed for the hub client only.
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(CLUB, HUB_CALLBACK, CLUB_SCOPE, CLUB_RESOURCE),
                "hubowner", "password123", AuthCodeFlow.pkce());
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "error")).isEqualTo("access_denied");
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code")).isNull();
    }

    @Test
    void clubTokenIsRefusedOnTheAdminApiWithTheProductionDecoder() throws Exception {
        AuthCodeFlow.TokenPair t = flow.clubTokens("clubowner", "password123");
        long id = userRepository.findByUsername("clubowner").orElseThrow().getId();
        mockMvc.perform(get("/api/v1/users/{id}", id).header("Authorization", "Bearer " + t.accessToken()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/clients").header("Authorization", "Bearer " + t.accessToken()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + t.accessToken()))
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(200));
        // Positive control: same claims re-signed with typ JWT reach the API (own record 200, admin API 403).
        String control = flow.resign(t.accessToken(), "JWT");
        mockMvc.perform(get("/api/v1/users/{id}", id).header("Authorization", "Bearer " + control))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/clients").header("Authorization", "Bearer " + control))
                .andExpect(status().isForbidden());
    }

    @Test
    void hubClientRegistrationAndTokenShapeAreUnchanged() throws Exception {
        var hub = registeredClients.findByClientId(HUB);
        assertThat(hub.getScopes()).containsExactlyInAnyOrder("mail:read", "calendar:read");
        assertThat(hub.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(10));
        assertThat(hub.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(hub.getTokenSettings().isReuseRefreshTokens()).isFalse();
        assertThat(hub.getClientSettings().<Object>getSetting(OidcClientProperties.AUDIENCE_BOUND_SETTING))
                .isEqualTo(Boolean.TRUE);
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        Map<String, Object> c = AuthCodeFlow.payload(t.accessToken());
        assertThat(AuthCodeFlow.audiences(c)).containsExactly(HUB_RESOURCE);
        assertThat(c).containsEntry("client_id", HUB);
        // hub secret is not the club secret
        flow.refreshPost(CLUB, HUB_SECRET, t.refreshToken(), null).andExpect(status().is4xxClientError());
    }
}
