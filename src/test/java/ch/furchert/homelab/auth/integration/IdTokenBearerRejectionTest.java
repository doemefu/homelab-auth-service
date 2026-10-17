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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An admin's ID token carries the same signature and {@code role} claim as the access token, but must
 * not authenticate against the admin API. Real database, real auth-code flow for furchert-ch.
 */
class IdTokenBearerRejectionTest extends AbstractIntegrationTest {

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

    @Test
    void adminApiAcceptsTheAccessTokenButNotTheIdToken() throws Exception {
        AuthCodeFlow flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        String secret = "pw-" + "x".repeat(12);
        flow.createUser("idtokenadmin", secret, Role.ADMIN);
        AuthCodeFlow.Req req = new AuthCodeFlow.Req(FC, FC_CALLBACK, "openid profile email", null);
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = AuthCodeFlow.param(
                flow.authorizeAs(req, "idtokenadmin", secret, p).getResponse().getRedirectedUrl(), "code");
        JsonNode body = flow.json(flow.exchangeBasic(FC, FC_SECRET, code, FC_CALLBACK, p, null)
                .andExpect(status().isOk()).andReturn());

        mockMvc.perform(get("/api/v1/users").header("Authorization", "Bearer " + body.get("access_token").asString()))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/users").header("Authorization", "Bearer " + body.get("id_token").asString()))
                .andExpect(status().isUnauthorized());
    }
}
