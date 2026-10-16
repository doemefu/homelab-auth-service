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
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Changing a user's role revokes the user's authorizations (refresh tokens) and consents, like setting the
 * user to INACTIVE. Refresh-grant access tokens are built from the principal stored at login, so a surviving
 * authorization would keep issuing tokens with the old role. Real database, real authorization-code flow.
 */
class UserRoleChangeRevocationTest extends AbstractIntegrationTest {

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

    private Integer authorizationRows(String principalName) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = ?",
                Integer.class, principalName);
    }
}
