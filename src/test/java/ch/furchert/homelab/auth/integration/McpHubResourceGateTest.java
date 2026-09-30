package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;


import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_CALLBACK;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gate G3 of docs/080 §4.5 (#107): RFC 8707 resource values for claude-mcp-hub at the authorization and
 * token endpoints, and both client authentication methods. Real application context and signed tokens.
 */
@ExtendWith(OutputCaptureExtension.class)
class McpHubResourceGateTest extends AbstractIntegrationTest {

    private static final String OTHER_RESOURCE = "https://other.example/mcp";

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
        flow.createUser("hubowner", "password123", Role.USER);
    }

    private String hubCode(String resourceOnAuthorize, AuthCodeFlow.Pkce p) throws Exception {
        return flow.hubCode(new AuthCodeFlow.Req(HUB, HUB_CALLBACK, HUB_SCOPE, resourceOnAuthorize),
                "hubowner", "password123", p);
    }

    @Test
    void tokenExchangeRejectsMismatchingResource(CapturedOutput out) throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = hubCode(HUB_RESOURCE, p);
        flow.exchangePost(HUB, HUB_SECRET, code, HUB_CALLBACK, p, OTHER_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
        assertThat(out.getOut()).contains(OTHER_RESOURCE).doesNotContain(HUB_SECRET);
    }

    @Test
    void tokenExchangeRejectsTrailingSlashVariant(CapturedOutput out) throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = hubCode(HUB_RESOURCE, p);
        flow.exchangePost(HUB, HUB_SECRET, code, HUB_CALLBACK, p, HUB_RESOURCE + "/")
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
        assertThat(out.getOut()).contains(HUB_RESOURCE + "/");
    }

    @Test
    void refreshRejectsMismatchingResource() throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), OTHER_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE).andExpect(status().isOk());   // not consumed
    }

    @Test
    void tokenExchangeRejectsSeveralValuesOneNotAllowed() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = hubCode(HUB_RESOURCE, p);
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code").param("code", code)
                        .param("redirect_uri", HUB_CALLBACK).param("code_verifier", p.verifier())
                        .param("client_id", HUB).param("client_secret", HUB_SECRET)
                        .param("resource", HUB_RESOURCE, OTHER_RESOURCE))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
    }

    @Test
    void refreshRejectsSeveralValuesOneNotAllowed() throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "refresh_token").param("refresh_token", t.refreshToken())
                        .param("client_id", HUB).param("client_secret", HUB_SECRET)
                        .param("resource", HUB_RESOURCE, OTHER_RESOURCE))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_target"));
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE).andExpect(status().isOk());   // not consumed
    }

    @Test
    void absentResourceIsAcceptedAndAudienceIsHardMapped() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = hubCode(null, p);
        JsonNode body = flow.json(flow.exchangePost(HUB, HUB_SECRET, code, HUB_CALLBACK, p, null)
                .andExpect(status().isOk()).andReturn());
        assertThat(AuthCodeFlow.audiences(AuthCodeFlow.payload(body.get("access_token").asString())))
                .containsExactly(HUB_RESOURCE);
        JsonNode refreshed = flow.json(flow.refreshPost(HUB, HUB_SECRET, body.get("refresh_token").asString(), null)
                .andExpect(status().isOk()).andReturn());
        assertThat(AuthCodeFlow.audiences(AuthCodeFlow.payload(refreshed.get("access_token").asString())))
                .containsExactly(HUB_RESOURCE);
    }

    @Test
    void clientSecretPostWorksForExchangeAndRefresh() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = hubCode(HUB_RESOURCE, p);
        JsonNode body = flow.json(flow.exchangePost(HUB, HUB_SECRET, code, HUB_CALLBACK, p, HUB_RESOURCE)
                .andExpect(status().isOk()).andReturn());
        flow.refreshPost(HUB, HUB_SECRET, body.get("refresh_token").asString(), HUB_RESOURCE)
                .andExpect(status().isOk());
    }

    @Test
    void clientSecretBasicWorksForExchange() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = hubCode(HUB_RESOURCE, p);
        flow.exchangeBasic(HUB, HUB_SECRET, code, HUB_CALLBACK, p, HUB_RESOURCE)
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").exists());
    }

    @Test
    void authorizeRejectsMismatchingResourceWithErrorRedirect(CapturedOutput out) throws Exception {
        MvcResult r = flow.authorizeAnonymous(
                new AuthCodeFlow.Req(HUB, HUB_CALLBACK, HUB_SCOPE, OTHER_RESOURCE), AuthCodeFlow.pkce());
        String location = r.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(HUB_CALLBACK);
        assertThat(AuthCodeFlow.param(location, "error")).isEqualTo("invalid_target");
        assertThat(AuthCodeFlow.param(location, "code")).isNull();
        assertThat(out.getOut()).contains(OTHER_RESOURCE);
    }
}
