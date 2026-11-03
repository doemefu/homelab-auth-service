package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.config.LoginThrottleProperties;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.security.LoginThrottle;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * #104 end to end over the real chains: form login and client authentication, with low thresholds set
 * on the bound properties for each test (the shared context keeps the throttle on with thresholds no
 * other test reaches).
 */
class LoginThrottleIntegrationTest extends AbstractIntegrationTest {

    private static final String PASSWORD = "password123";
    private static final String CF = "CF-Connecting-IP";

    @Autowired
    MockMvc mockMvc;
    @Autowired
    LoginThrottle throttle;
    @Autowired
    LoginThrottleProperties props;
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

    private LoginThrottleProperties.Limits user;
    private LoginThrottleProperties.Limits ip;
    private LoginThrottleProperties.Limits client;
    private AuthCodeFlow flow;

    @BeforeEach
    void lowerThresholds() {
        user = props.getUser();
        ip = props.getIp();
        client = props.getClient();
        props.setUser(new LoginThrottleProperties.Limits(3, Duration.ofMinutes(15), Duration.ofMinutes(5)));
        props.setIp(new LoginThrottleProperties.Limits(50, Duration.ofMinutes(15), Duration.ofMinutes(15)));
        props.setClient(new LoginThrottleProperties.Limits(3, Duration.ofMinutes(5), Duration.ofMinutes(5)));
        throttle.clear();
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
    }

    @AfterEach
    void restoreThresholds() {
        props.setUser(user);
        props.setIp(ip);
        props.setClient(client);
        throttle.clear();
    }

    private String login(String username, String password, String clientIp) throws Exception {
        return mockMvc.perform(post("/login").param("username", username).param("password", password)
                        .header(CF, clientIp).with(csrf()))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    @Test
    void usernameIsLockedAcrossIpsAndTheResponseDoesNotRevealWhetherItExists() throws Exception {
        flow.createUser("throttle-u1", PASSWORD, Role.USER);
        for (int i = 1; i <= 3; i++) {
            assertThat(login("throttle-u1", "wrong", "203.0.113." + i)).isEqualTo("/login?error");
            assertThat(login("nobody-u1", "wrong", "203.0.113." + (10 + i))).isEqualTo("/login?error");
        }
        // Even the correct password, from a fresh IP, is not checked while the username is locked.
        assertThat(login("throttle-u1", PASSWORD, "198.51.100.1")).isEqualTo("/login?throttled");
        assertThat(login("nobody-u1", PASSWORD, "198.51.100.2")).isEqualTo("/login?throttled");
    }

    @Test
    void queryStringCredentialsCannotBypassTheLock() throws Exception {
        flow.createUser("throttle-u2", PASSWORD, Role.USER);
        for (int i = 1; i <= 3; i++) {
            login("throttle-u2", "wrong", "203.0.113." + (20 + i));
        }
        String location = mockMvc.perform(post("/login?username=throttle-u2&password=" + PASSWORD)
                        .contentType(MediaType.TEXT_PLAIN).content("x").header(CF, "198.51.100.3").with(csrf()))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(location).isEqualTo("/login?throttled");
    }

    @Test
    void ipIsLockedForEveryUsername() throws Exception {
        props.setIp(new LoginThrottleProperties.Limits(3, Duration.ofMinutes(15), Duration.ofMinutes(15)));
        flow.createUser("throttle-u3", PASSWORD, Role.USER);
        for (int i = 1; i <= 3; i++) {
            login("spray" + i, "wrong", "203.0.113.50");
        }
        assertThat(login("throttle-u3", PASSWORD, "203.0.113.50")).isEqualTo("/login?throttled");
        assertThat(login("throttle-u3", PASSWORD, "203.0.113.51")).doesNotContain("error", "throttled");
    }

    @Test
    void successResetsTheUsernameCount() throws Exception {
        flow.createUser("throttle-u4", PASSWORD, Role.USER);
        login("throttle-u4", "wrong", "203.0.113.30");
        login("throttle-u4", "wrong", "203.0.113.30");
        assertThat(login("throttle-u4", PASSWORD, "203.0.113.30")).doesNotContain("error", "throttled");
        login("throttle-u4", "wrong", "203.0.113.30");
        login("throttle-u4", "wrong", "203.0.113.30");
        assertThat(login("throttle-u4", PASSWORD, "203.0.113.30")).doesNotContain("error", "throttled");
    }

    @Test
    void successfulLoginsNeverLock() throws Exception {
        flow.createUser("throttle-u6", PASSWORD, Role.USER);
        for (int i = 0; i < 10; i++) {
            assertThat(login("throttle-u6", PASSWORD, "203.0.113.70")).doesNotContain("error", "throttled");
        }
    }

    @Test
    void aKnownNetworkKeepsWorkingWhileTheUsernameIsLocked() throws Exception {
        flow.createUser("throttle-u5", PASSWORD, Role.USER);
        assertThat(login("throttle-u5", PASSWORD, "192.0.2.10")).doesNotContain("error", "throttled");
        for (int i = 1; i <= 3; i++) {
            login("throttle-u5", "wrong", "203.0.113." + (60 + i));
        }
        assertThat(login("throttle-u5", PASSWORD, "198.51.100.9")).isEqualTo("/login?throttled");
        assertThat(login("throttle-u5", PASSWORD, "192.0.2.10")).doesNotContain("error", "throttled");
    }

    private MockHttpServletRequestBuilder clientCredentials(String clientId, String secret, String clientIp,
                                                            boolean basic) {
        MockHttpServletRequestBuilder b = post("/oauth2/token").param("grant_type", "client_credentials")
                .header(CF, clientIp);
        if (basic) {
            return b.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                    (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        }
        return b.param("client_id", clientId).param("client_secret", secret);
    }

    @Test
    void clientIsLockedPerIpAndClientIdWith429() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(clientCredentials("device-service", "wrong", "203.0.113.80", i % 2 == 0))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("invalid_client"))
                    .andExpect(jsonPath("$.error_description").doesNotExist());   // SAS default body kept
        }
        mockMvc.perform(clientCredentials("device-service", "device-service-secret", "203.0.113.80", true))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", org.hamcrest.Matchers.matchesPattern("29[5-9]|300")))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.error").value("temporarily_unavailable"));
        mockMvc.perform(clientCredentials("device-service", "device-service-secret", "203.0.113.81", true))
                .andExpect(status().isOk());
        mockMvc.perform(clientCredentials("furchert-ch", "furchert-ch-secret", "203.0.113.80", true))
                .andExpect(status().isOk());
    }

    @Test
    void unknownClientIdsAreNeverLocked() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(clientCredentials("no-such-client", "x", "203.0.113.90", false))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void nonClientErrorsKeepSasDefaultStatus() throws Exception {
        // A repeated client_secret parameter: invalid_request (400) from SAS's client authentication.
        mockMvc.perform(clientCredentials("device-service", "device-service-secret", "203.0.113.95", false)
                        .param("client_secret", "other"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void hubRefreshKeepsWorkingWhenOthersFailWithTheHubIdFromTheSameIp() throws Exception {
        flow.createUser("hubowner", PASSWORD, Role.USER);
        AuthCodeFlow.TokenPair tokens = flow.hubTokens("hubowner", PASSWORD);
        // Same source IP (MockMvc: 127.0.0.1, no CF header), wrong secrets for the hub's client id.
        for (int i = 0; i < 3; i++) {
            flow.refreshPost(AuthCodeFlow.HUB, "guess" + i, tokens.refreshToken(), AuthCodeFlow.HUB_RESOURCE)
                    .andExpect(status().isUnauthorized());
        }
        flow.refreshPost(AuthCodeFlow.HUB, "guess-again", tokens.refreshToken(), AuthCodeFlow.HUB_RESOURCE)
                .andExpect(status().isTooManyRequests());
        MvcResult refreshed = flow.refreshPost(AuthCodeFlow.HUB, AuthCodeFlow.HUB_SECRET, tokens.refreshToken(),
                        AuthCodeFlow.HUB_RESOURCE)
                .andExpect(status().isOk()).andReturn();
        assertThat(flow.json(refreshed).get("access_token").asString()).isNotBlank();
    }
}
