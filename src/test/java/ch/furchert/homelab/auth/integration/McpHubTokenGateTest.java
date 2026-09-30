package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.config.OidcClientProperties;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_CALLBACK;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gate tests of docs/080 §4.5 (G1, G1b, G1c, G2; #107). MUST NOT use {@code @MockitoBean JwtDecoder} or
 * {@code SecurityMockMvcRequestPostProcessors.jwt()}: they exercise the production
 * {@code jwtDecoder(jwkSource)} bean and really signed tokens.
 */
@ExtendWith(OutputCaptureExtension.class)
class McpHubTokenGateTest extends AbstractIntegrationTest {

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
    ApplicationContext applicationContext;
    @Autowired
    RegisteredClientRepository registeredClients;
    @Autowired
    OidcClientProperties props;
    @Autowired
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer;

    private AuthCodeFlow flow;

    @BeforeEach
    void setUp() {
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("hubowner", "password123", Role.USER);
        flow.createUser("hubadmin", "password123", Role.ADMIN);
    }

    @Test // G1
    @SuppressWarnings("unchecked")
    void hubTokenHasTheSpec080Shape() throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        Map<String, Object> h = AuthCodeFlow.header(t.accessToken());
        Map<String, Object> c = AuthCodeFlow.payload(t.accessToken());
        assertThat(h).containsEntry("typ", "at+jwt").containsEntry("alg", "RS256").containsEntry("kid", "auth-service-v1");
        // Exactly one audience, the hub URL (a single audience is serialised as a string, docs/080 §4.2).
        assertThat(AuthCodeFlow.audiences(c)).containsExactly("https://mcp.furchert.ch/mcp");
        assertThat(c).containsEntry("client_id", "claude-mcp-hub").containsEntry("sub", "hubowner")
                .containsEntry("iss", "https://auth.test.local")
                .doesNotContainKey("role").doesNotContainKey("device_id");
        assertThat((List<String>) c.get("scope")).containsExactlyInAnyOrder("mail:read", "calendar:read")
                .doesNotContain("openid");
        assertThat(((Number) c.get("exp")).longValue() - ((Number) c.get("iat")).longValue()).isEqualTo(600L);
        assertThat(c).containsKeys("nbf", "jti");
    }

    @Test // G1 — no ID token (asserted inside AuthCodeFlow.hubTokens), openid cannot be requested
    void hubClientIssuesNoIdTokenAndRefusesOpenid() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        MvcResult r = flow.authorizeAnonymous(new AuthCodeFlow.Req(HUB, HUB_CALLBACK, "openid mail:read", HUB_RESOURCE), p);
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "error")).isEqualTo("invalid_scope");
    }

    @Test // G1b
    void refreshWorksAfterShapingAndRotates() throws Exception {
        AuthCodeFlow.TokenPair first = flow.hubTokens("hubowner", "password123");
        JsonNode refreshed = flow.json(flow.refreshPost(HUB, HUB_SECRET, first.refreshToken(), HUB_RESOURCE)
                .andExpect(status().isOk()).andExpect(jsonPath("$.id_token").doesNotExist()).andReturn());
        String access2 = refreshed.get("access_token").asString();
        String refresh2 = refreshed.get("refresh_token").asString();
        assertThat(refresh2).isNotEqualTo(first.refreshToken());
        assertThat(AuthCodeFlow.header(access2)).containsEntry("typ", "at+jwt");
        assertThat(AuthCodeFlow.audiences(AuthCodeFlow.payload(access2))).containsExactly("https://mcp.furchert.ch/mcp");
        assertThat(AuthCodeFlow.payload(access2)).containsEntry("client_id", HUB).doesNotContainKey("role");
        // superseded refresh token
        flow.refreshPost(HUB, HUB_SECRET, first.refreshToken(), HUB_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
        // rotated token works again (second refresh reads the persisted claims once more)
        flow.refreshPost(HUB, HUB_SECRET, refresh2, HUB_RESOURCE).andExpect(status().isOk());
    }

    @Test // G1b — the audience-bound marker is persisted in client_settings and survives the JDBC round trip
    void refreshWorksWithTheAudienceBoundMarkerPersisted() throws Exception {
        assertThat(registeredClients.findByClientId(HUB).getClientSettings()
                .<Object>getSetting(OidcClientProperties.AUDIENCE_BOUND_SETTING)).isEqualTo(Boolean.TRUE);
        assertThat(jdbc.queryForObject("SELECT client_settings FROM oauth2_registered_client WHERE client_id = ?",
                String.class, HUB)).contains(OidcClientProperties.AUDIENCE_BOUND_SETTING);
        AuthCodeFlow.TokenPair first = flow.hubTokens("hubowner", "password123");
        String refresh2 = flow.json(flow.refreshPost(HUB, HUB_SECRET, first.refreshToken(), HUB_RESOURCE)
                .andExpect(status().isOk()).andReturn()).get("refresh_token").asString();
        flow.refreshPost(HUB, HUB_SECRET, refresh2, HUB_RESOURCE).andExpect(status().isOk());
    }

    @Test // G1c — a row that outlives its configuration fails closed at every hook
    void markedClientWithoutDefinitionGetsNoCodeAndNoToken(CapturedOutput out) throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        int index = props.getClients().indexOf(props.findClient(HUB).orElseThrow());
        OidcClientProperties.ClientDefinition hubDefinition = props.getClients().remove(index);   // entry removed/renamed
        try {
            // token endpoint: no refresh, no access token
            flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), null)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("unauthorized_client"))
                    .andExpect(jsonPath("$.access_token").doesNotExist());
            // authorization endpoint: error redirect, no code, no consent page
            MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(HUB, HUB_CALLBACK, HUB_SCOPE, null),
                    "hubowner", "password123", AuthCodeFlow.pkce());
            assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "error")).isEqualTo("access_denied");
            assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code")).isNull();
            // token customizer, called directly (last line of defence behind the guard)
            JwtEncodingContext context = JwtEncodingContext
                    .with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder())
                    .registeredClient(registeredClients.findByClientId(HUB))
                    .principal(new UsernamePasswordAuthenticationToken("hubowner", null, List.of()))
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .build();
            assertThatThrownBy(() -> tokenCustomizer.customize(context))
                    .isInstanceOf(OAuth2AuthenticationException.class);
            // Only the rejection lines are checked; earlier output of the hubTokens flow is not this test's subject.
            List<String> rejectionLines = out.getOut().lines()
                    .filter(line -> line.contains("marked audience-bound but has no configured audience")).toList();
            assertThat(rejectionLines).isNotEmpty()
                    .allSatisfy(line -> assertThat(line).contains(HUB)
                            .doesNotContain("hubowner").doesNotContain(HUB_SECRET));
        } finally {
            props.getClients().add(index, hubDefinition);
        }
        // configuration restored → the same refresh token works again (it was never consumed)
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE).andExpect(status().isOk());
    }

    @Test // G2 — nothing may replace the bearer-token converter of the resource-server chains
    void noAuthenticationConverterBeanIsRegistered() {
        assertThat(applicationContext.getBeanNamesForType(
                org.springframework.security.web.authentication.AuthenticationConverter.class)).isEmpty();
    }

    @ParameterizedTest // G2
    @ValueSource(strings = {"hubowner", "hubadmin"})
    void hubTokenIsRejectedByTheAdminApiWithTheProductionDecoder(String username) throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens(username, "password123");
        long id = userRepository.findByUsername(username).orElseThrow().getId();
        mockMvc.perform(get("/api/v1/users/{id}", id).header("Authorization", "Bearer " + t.accessToken()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/clients").header("Authorization", "Bearer " + t.accessToken()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + t.accessToken()))
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(200));

        // Positive control through the same real filter chain: same claims, re-signed with the service's
        // real key and typ JWT. Exact statuses, so a 401 "for the wrong reason" (no bearer token extracted,
        // wrong decoder) cannot pass the gate: own user record → 200; device-client admin API → 403
        // (authenticated, but neither role ADMIN nor scope clients:admin — the hub token carries no role).
        String control = flow.resign(t.accessToken(), "JWT");
        mockMvc.perform(get("/api/v1/users/{id}", id).header("Authorization", "Bearer " + control))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/clients").header("Authorization", "Bearer " + control))
                .andExpect(status().isForbidden());
    }
}
