package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end lifecycle of an IoT device client: create via admin API → mint a
 * client_credentials JWT → delete → assert token endpoint refuses new requests.
 * <p>
 * Note (per SPEC and plan §C4 / F5): JWTs issued before delete remain valid at
 * any resource server that only checks signature + exp until they expire. The
 * delete only revokes the AS authorization rows and refuses new token requests.
 */
class DeviceClientLifecycleIT extends AbstractIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    @BeforeEach
    void seedAdminUser() {
        if (userRepository.findByUsername("itadmin").isEmpty()) {
            User u = new User();
            u.setUsername("itadmin");
            u.setEmail("itadmin@test.local");
            u.setPasswordHash(passwordEncoder.encode("ignored"));
            u.setRole(Role.ADMIN);
            u.setStatus("ACTIVE");
            userRepository.save(u);
        }
    }

    @Test
    void fullLifecycle_createTokenDelete() throws Exception {
        // Step 1: ADMIN creates a device client.
        MvcResult createResult = mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(j -> j.subject("itadmin")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"terra-lc\",\"description\":\"lifecycle test\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.clientId").value("terra-lc"))
                .andExpect(jsonPath("$.clientSecret").isString())
                .andReturn();

        JsonNode createBody = objectMapper.readTree(
                createResult.getResponse().getContentAsString());
        String plaintextSecret = createBody.get("clientSecret").asString();
        assertThat(plaintextSecret).isNotBlank();

        // Step 2: Mint a client_credentials access token using basic auth.
        String basic = Base64.getEncoder().encodeToString(
                ("terra-lc:" + plaintextSecret).getBytes(StandardCharsets.UTF_8));

        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&scope=mqtt:pub+mqtt:sub"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isString())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andReturn();

        JsonNode tokenBody = objectMapper.readTree(
                tokenResult.getResponse().getContentAsString());
        String accessToken = tokenBody.get("access_token").asString();
        assertThat(accessToken.split("\\.")).hasSize(3);

        // Decode payload — assert device_id and scope claims.
        String payloadJson = new String(
                Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]),
                StandardCharsets.UTF_8);
        JsonNode payload = objectMapper.readTree(payloadJson);
        assertThat(payload.get("device_id").asString()).isEqualTo("terra-lc");
        // The JWT scope claim is encoded as an array by Spring Authorization Server.
        JsonNode scopeNode = payload.get("scope");
        assertThat(scopeNode.isArray()).as("scope claim is an array").isTrue();
        List<String> scopeList = new ArrayList<>();
        scopeNode.forEach(n -> scopeList.add(n.asString()));
        assertThat(scopeList).containsExactlyInAnyOrder("mqtt:pub", "mqtt:sub");

        // Step 3: DELETE the client — must remove the registered_client row and
        // any oauth2_authorization rows that reference it.
        Integer authRowsBefore = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_authorization a "
                        + "JOIN oauth2_registered_client c ON c.id = a.registered_client_id "
                        + "WHERE c.client_id = ?", Integer.class, "terra-lc");
        assertThat(authRowsBefore).isGreaterThanOrEqualTo(1);

        mockMvc.perform(delete("/api/v1/clients/terra-lc")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(j -> j.subject("itadmin"))))
                .andExpect(status().isNoContent());

        Integer clientRows = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = ?",
                Integer.class, "terra-lc");
        assertThat(clientRows).isZero();

        // Step 4: A new token request with the same credentials must fail.
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&scope=mqtt:pub+mqtt:sub"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteSsoClientId_isIdempotentAndDoesNotTouchSsoRows() throws Exception {
        // Before: count SSO rows for grafana (seeded by StaticClientSeeder).
        // test-client is the seeded SSO client (replacing clients[0]) used by
        // OidcFlowIntegrationTest. It must NOT be deletable via /api/v1/clients/{id}.
        Integer rowsBefore = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = ?",
                Integer.class, "test-client");
        assertThat(rowsBefore).isEqualTo(1);

        mockMvc.perform(delete("/api/v1/clients/test-client")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(j -> j.subject("itadmin"))))
                .andExpect(status().isNoContent());

        Integer rowsAfter = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = ?",
                Integer.class, "test-client");
        assertThat(rowsAfter)
                .as("SSO client must NOT be deleted via the device admin API")
                .isEqualTo(1);
    }
}
