package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The admin API accepts only first-party audiences (#153): an ADMIN's access token issued to another relying
 * party (LiteLLM) is refused there, while the same token keeps working at {@code /userinfo}. The accepted
 * callers are covered with real tokens elsewhere: furchert-ch ({@code IdTokenBearerRejectionTest}),
 * device-service ({@code ExistingClientsUnchangedGateTest}) and data-service ({@code LoginEventOutboxIntegrationTest}).
 */
class ApiAudienceAllowlistTest extends AbstractIntegrationTest {

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

    @Test
    void anAdminTokenOfAnotherRelyingPartyIsRefusedOnTheAdminApiButWorksAtUserinfo() throws Exception {
        AuthCodeFlow flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        String secret = "pw-" + "z".repeat(12);
        flow.createUser("audadmin", secret, Role.ADMIN);
        AuthCodeFlow.Req req = new AuthCodeFlow.Req("litellm", "https://ai.test.local/callback", "openid profile email", null);
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = AuthCodeFlow.param(
                flow.authorizeAs(req, "audadmin", secret, p).getResponse().getRedirectedUrl(), "code");
        JsonNode body = flow.json(flow.exchangeBasic("litellm", "test-secret-litellm", code,
                "https://ai.test.local/callback", p, null).andExpect(status().isOk()).andReturn());
        String accessToken = body.get("access_token").asString();
        long id = userRepository.findByUsername("audadmin").orElseThrow().getId();

        mockMvc.perform(get("/api/v1/users").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/users/" + id).header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));

        // Positive control through the same chain: the same claims with a first-party audience are accepted.
        String control = flow.resign(accessToken, "JWT", "furchert-ch");
        mockMvc.perform(get("/api/v1/users").header("Authorization", "Bearer " + control))
                .andExpect(status().isOk());
    }
}
