package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.config.OidcClientProperties;
import ch.furchert.homelab.auth.dto.UpdateUserRequest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.service.UserService;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Changing a user's role revokes the user's authorizations (refresh tokens) and consents, like setting the
 * user to INACTIVE. A login session from before the change never yields more than the lower of the old and
 * new role: a demotion applies at once, a promotion at the next sign-in. Real database, real auth-code flow.
 */
class UserRoleChangeRevocationTest extends AbstractIntegrationTest {

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
    @Autowired
    UserService userService;
    @Autowired
    OidcClientProperties props;

    @Test
    void roleChangeRevokesAuthorizationsAndConsentsButUnchangedRoleDoesNot() throws Exception {
        AuthCodeFlow flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("hubdemoted", "password123", Role.ADMIN);
        OidcClientProperties.ClientDefinition hub = props.findClient(HUB).orElseThrow();
        List<String> original = new ArrayList<>(hub.getAllowedUsers());
        hub.setAllowedUsers(new ArrayList<>(List.of("hubowner", "hubadmin", "hubdemoted")));
        try {
            long id = userRepository.findByUsername("hubdemoted").orElseThrow().getId();
            AuthCodeFlow.TokenPair t = flow.hubTokens("hubdemoted", "password123");
            assertThat(flow.consentRows(HUB, "hubdemoted")).isOne();

            // Same role: nothing is revoked.
            userService.updateUser(id, new UpdateUserRequest(null, null, Role.ADMIN, null));
            assertThat(flow.consentRows(HUB, "hubdemoted")).isOne();
            assertThat(authorizationRows("hubdemoted")).isPositive();

            userService.updateUser(id, new UpdateUserRequest(null, null, Role.USER, null));

            assertThat(userRepository.findByUsername("hubdemoted").orElseThrow().getRole()).isEqualTo(Role.USER);
            assertThat(flow.consentRows(HUB, "hubdemoted")).isZero();
            assertThat(authorizationRows("hubdemoted")).isZero();
            flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE)
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
        } finally {
            hub.setAllowedUsers(original);
        }
    }

    @Test
    void tokensFromALoginSessionOpenedBeforeTheRoleChangeCarryTheNewRole() throws Exception {
        AuthCodeFlow flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("fcdemoted", "password123", Role.ADMIN);
        long id = userRepository.findByUsername("fcdemoted").orElseThrow().getId();
        AuthCodeFlow.Req req = new AuthCodeFlow.Req(FC, FC_CALLBACK, "openid profile email", null);

        AuthCodeFlow.Pkce p1 = AuthCodeFlow.pkce();
        MvcResult first = flow.authorizeAs(req, "fcdemoted", "password123", p1);
        MockHttpSession session = (MockHttpSession) first.getRequest().getSession();
        assertThat(role(flow, first, p1)).isEqualTo("ADMIN");

        userService.updateUser(id, new UpdateUserRequest(null, null, Role.USER, null));

        // Same browser session, no new sign-in: the session still holds the ROLE_ADMIN principal.
        AuthCodeFlow.Pkce p2 = AuthCodeFlow.pkce();
        MvcResult second = mockMvc.perform(AuthCodeFlow.authorize(req, p2).session(session)).andReturn();
        assertThat(role(flow, second, p2)).isEqualTo("USER");
    }

    @Test
    void aPromotionAppliesOnlyAfterANewSignIn() throws Exception {
        // Same path as a username reused after a rename: the session's role differs from the row's.
        AuthCodeFlow flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("fcpromoted", "password123", Role.USER);
        long id = userRepository.findByUsername("fcpromoted").orElseThrow().getId();
        AuthCodeFlow.Req req = new AuthCodeFlow.Req(FC, FC_CALLBACK, "openid profile email", null);

        AuthCodeFlow.Pkce p1 = AuthCodeFlow.pkce();
        MvcResult first = flow.authorizeAs(req, "fcpromoted", "password123", p1);
        MockHttpSession session = (MockHttpSession) first.getRequest().getSession();
        assertThat(role(flow, first, p1)).isEqualTo("USER");

        userService.updateUser(id, new UpdateUserRequest(null, null, Role.ADMIN, null));

        AuthCodeFlow.Pkce p2 = AuthCodeFlow.pkce();
        MvcResult second = mockMvc.perform(AuthCodeFlow.authorize(req, p2).session(session)).andReturn();
        assertThat(role(flow, second, p2)).isEqualTo("USER");

        AuthCodeFlow.Pkce p3 = AuthCodeFlow.pkce();
        assertThat(role(flow, flow.authorizeAs(req, "fcpromoted", "password123", p3), p3)).isEqualTo("ADMIN");
    }

    private String role(AuthCodeFlow flow, MvcResult authorized, AuthCodeFlow.Pkce p) throws Exception {
        String code = AuthCodeFlow.param(authorized.getResponse().getRedirectedUrl(), "code");
        JsonNode body = flow.json(flow.exchangeBasic(FC, FC_SECRET, code, FC_CALLBACK, p, null)
                .andExpect(status().isOk()).andReturn());
        Map<String, Object> access = AuthCodeFlow.payload(body.get("access_token").asString());
        Map<String, Object> id = AuthCodeFlow.payload(body.get("id_token").asString());
        assertThat(id.get("role")).isEqualTo(access.get("role"));
        return (String) access.get("role");
    }

    private Integer authorizationRows(String principalName) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = ?",
                Integer.class, principalName);
    }
}
