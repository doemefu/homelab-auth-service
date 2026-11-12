package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Password policy and hashing (#150) through the real filter chains and database: API rejections name the
 * rule, client secrets stay at bcrypt cost 10, and user hashes move to the configured cost at login.
 */
class PasswordPolicyIntegrationTest extends AbstractIntegrationTest {

    private static final String DEVICE_SECRET = "device-service-secret";   // AbstractIntegrationTest's value

    @Autowired
    MockMvc mockMvc;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    // --- API: the failed rule is named under the request field ---

    @Test
    void createUser_withACommonPassword_isRejectedNamingTheRule() throws Exception {
        mockMvc.perform(post("/api/v1/users").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"policy-user-1\",\"email\":\"policy1@test.local\","
                                + "\"password\":\"!qazxsw2#edcvfr4\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("password does not meet the policy"))
                .andExpect(jsonPath("$.details.password").value("too common: it appears in lists of breached passwords"));
        assertThat(userRepository.findByUsername("policy-user-1")).isEmpty();
    }

    @Test
    void resetPassword_equalToTheEmail_isRejectedNamingTheRule() throws Exception {
        User user = saveUser("policy-user-2", passwordEncoder.encode("a-valid-old-passphrase"));
        mockMvc.perform(post("/api/v1/users/" + user.getId() + "/reset-password")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"newPassword\":\"policy-user-2@test.local\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details.newPassword").value("must not be the username or the e-mail address"));
    }

    @Test
    void createUser_withA14CharacterPassword_isRejected() throws Exception {
        mockMvc.perform(post("/api/v1/users").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"policy-user-3\",\"email\":\"policy3@test.local\","
                                + "\"password\":\"k9-unlisted-q7\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details.password").exists());
    }

    // --- client secrets: cost 10, never re-encoded at the user cost ---

    @Test
    void cost10ClientSecret_isNotReEncodedAfterClientCredentials() throws Exception {
        String stored = "{bcrypt}" + new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2Y, 10)
                .encode(DEVICE_SECRET);
        setDeviceServiceSecret(stored);

        clientCredentials();

        assertThat(deviceServiceSecret()).isEqualTo(stored);
    }

    @Test
    void noopClientSecret_isReEncodedAtCost10() throws Exception {
        setDeviceServiceSecret("{noop}" + DEVICE_SECRET);

        clientCredentials();

        assertThat(deviceServiceSecret()).matches("\\{bcrypt}\\$2a\\$10\\$.{53}");
        clientCredentials();                                              // the new hash still verifies
    }

    // --- user hashes: re-encoded at the configured cost on the next successful login ---

    @ParameterizedTest
    @ValueSource(strings = {"{bcrypt}", ""})
    void legacyCost10UserHash_isUpgradedOnlyBySuccessfulLogin(String prefix) throws Exception {
        String username = "upgrade-user" + (prefix.isEmpty() ? "-unprefixed" : "-prefixed");
        String password = "an-upgrade-test-passphrase";
        String legacy = prefix + new BCryptPasswordEncoder(10).encode(password);
        userRepository.findByUsername(username).ifPresent(userRepository::delete);
        saveUser(username, legacy);

        login(username, "a-wrong-passphrase-123", "/login?error");
        assertThat(storedHash(username)).isEqualTo(legacy);

        login(username, password, "/");
        String upgraded = storedHash(username);
        assertThat(upgraded).matches("\\{bcrypt}\\$2a\\$12\\$.{53}");
        assertThat(passwordEncoder.matches(password, upgraded)).isTrue();
    }

    private void login(String username, String password, String expectedRedirect) throws Exception {
        mockMvc.perform(post("/login").param("username", username).param("password", password).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(expectedRedirect));
    }

    private User saveUser(String username, String hash) {
        User user = userRepository.findByUsername(username).orElseGet(User::new);
        user.setUsername(username);
        user.setEmail(username + "@test.local");
        user.setPasswordHash(hash);
        user.setRole(Role.USER);
        user.setStatus("ACTIVE");
        return userRepository.save(user);
    }

    private String storedHash(String username) {
        return userRepository.findByUsername(username).orElseThrow().getPasswordHash();
    }

    private void clientCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token").param("grant_type", "client_credentials").param("scope", "clients:admin")
                        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                                ("device-service:" + DEVICE_SECRET).getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isOk());
    }

    private void setDeviceServiceSecret(String value) {
        jdbc.update("UPDATE oauth2_registered_client SET client_secret = ? WHERE client_id = 'device-service'", value);
    }

    private String deviceServiceSecret() {
        return jdbc.queryForObject(
                "SELECT client_secret FROM oauth2_registered_client WHERE client_id = 'device-service'", String.class);
    }
}
