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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_CALLBACK;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Setting a user to INACTIVE revokes the user's authorizations (refresh tokens) and consents, like
 * deleting the user (#107). Reactivation restores nothing: the user has to sign in again and sees the
 * consent page again. Real database, real authorization-code flow.
 */
class UserDeactivationRevocationTest extends AbstractIntegrationTest {

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
    void deactivationRevokesAuthorizationsAndConsentsAndReactivationRestoresNothing() throws Exception {
        AuthCodeFlow flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("hubpaused", "password123", Role.USER);
        OidcClientProperties.ClientDefinition hub = props.findClient(HUB).orElseThrow();
        List<String> original = new ArrayList<>(hub.getAllowedUsers());
        hub.setAllowedUsers(new ArrayList<>(List.of("hubowner", "hubadmin", "hubpaused")));
        try {
            long id = userRepository.findByUsername("hubpaused").orElseThrow().getId();
            AuthCodeFlow.TokenPair t = flow.hubTokens("hubpaused", "password123");
            assertThat(flow.consentRows(HUB, "hubpaused")).isOne();

            userService.updateUser(id, new UpdateUserRequest(null, null, null, "INACTIVE"));

            assertThat(flow.consentRows(HUB, "hubpaused")).isZero();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = 'hubpaused'",
                    Integer.class)).isZero();
            flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE)
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));

            // Reactivation restores nothing: the old refresh token stays dead, a new login shows the consent page.
            userService.updateUser(id, new UpdateUserRequest(null, null, null, "ACTIVE"));
            flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE)
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
            MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(HUB, HUB_CALLBACK, HUB_SCOPE, HUB_RESOURCE),
                    "hubpaused", "password123", AuthCodeFlow.pkce());
            assertThat(r.getResponse().getStatus()).isEqualTo(200);   // consent page again
        } finally {
            hub.setAllowedUsers(original);
        }
    }
}
