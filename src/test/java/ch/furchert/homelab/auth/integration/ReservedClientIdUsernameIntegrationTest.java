package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * #143: registered client ids are reserved as usernames (case-insensitive), and a device client cannot
 * take an existing username. Real controllers, service and database; every row created here is removed.
 */
class ReservedClientIdUsernameIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JdbcTemplate jdbc;

    private ResultActions asAdmin(MockHttpServletRequestBuilder request, String json) throws Exception {
        return mockMvc.perform(request.with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                        .jwt(j -> j.subject("wa5-admin")))
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions createUser(String username) throws Exception {
        return asAdmin(post("/api/v1/users"), "{\"username\":\"" + username + "\",\"email\":\"" + username
                + "@test.local\",\"password\":\"password123\"}");
    }

    private void deleteUser(String username) {
        jdbc.update("DELETE FROM users WHERE username = ?", username);
    }

    @Test
    void creatingAUserNamedLikeAStoredClientIsRejected() throws Exception {
        try {
            createUser("furchert-ch").andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("username not available"))
                    .andExpect(jsonPath("$.details.username").value("not available"));
            createUser("HomeAssistant").andExpect(status().isBadRequest());
            assertThat(userRepository.findByUsername("furchert-ch")).isEmpty();
            assertThat(userRepository.findByUsername("HomeAssistant")).isEmpty();
        } finally {
            deleteUser("furchert-ch");
            deleteUser("HomeAssistant");
        }
    }

    @Test
    void creatingAUserNamedLikeADeviceClientIsRejected() throws Exception {
        String clientId = "wa5-dev-reserved";
        try {
            asAdmin(post("/api/v1/clients"), "{\"clientId\":\"" + clientId + "\"}").andExpect(status().isCreated());

            createUser(clientId).andExpect(status().isBadRequest());
            createUser("WA5-Dev-Reserved").andExpect(status().isBadRequest());
            assertThat(userRepository.findByUsername(clientId)).isEmpty();
        } finally {
            jdbc.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", clientId);
        }
    }

    @Test
    void renamingAUserToAClientIdIsRejectedAndKeepsTheName() throws Exception {
        String name = "wa5-rename-user";
        try {
            User user = new User();
            user.setUsername(name);
            user.setEmail(name + "@test.local");
            user.setPasswordHash(passwordEncoder.encode("password123"));
            user.setRole(Role.USER);
            user.setStatus("ACTIVE");
            long id = userRepository.save(user).getId();

            asAdmin(put("/api/v1/users/" + id), "{\"username\":\"Device-Service\"}")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("username not available"));

            assertThat(userRepository.findById(id).orElseThrow().getUsername()).isEqualTo(name);
        } finally {
            deleteUser(name);
        }
    }

    @Test
    void creatingADeviceClientNamedLikeAnExistingUserIsRejected() throws Exception {
        String name = "wa5-dev-taken";
        try {
            createUser(name).andExpect(status().isCreated());

            asAdmin(post("/api/v1/clients"), "{\"clientId\":\"" + name + "\"}")
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.error").value("client id not available"))
                    .andExpect(jsonPath("$.details.clientId").value("not available"));
            Integer rows = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = ?", Integer.class, name);
            assertThat(rows).isZero();
        } finally {
            jdbc.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", name);
            deleteUser(name);
        }
    }

    @Test
    void creatingADeviceClientNamedLikeAWhitespacePaddedUserIsRejected() throws Exception {
        String stored = " WA5-Dev-Padded ";
        String clientId = "wa5-dev-padded";
        try {
            User user = new User();
            user.setUsername(stored);
            user.setEmail("wa5-dev-padded@test.local");
            user.setPasswordHash(passwordEncoder.encode("password123"));
            user.setRole(Role.USER);
            user.setStatus("ACTIVE");
            userRepository.save(user);

            asAdmin(post("/api/v1/clients"), "{\"clientId\":\"" + clientId + "\"}")
                    .andExpect(status().isConflict());
        } finally {
            jdbc.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", clientId);
            deleteUser(stored);
        }
    }

    @Test
    void ordinaryNamesStillWork() throws Exception {
        String name = "wa5-ordinary";
        try {
            createUser(name).andExpect(status().isCreated());
        } finally {
            deleteUser(name);
        }
    }
}
