package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class OidcFlowIntegrationTest extends AbstractIntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    @BeforeEach
    void createTestUser() {
        if (userRepository.findByUsername("testuser").isEmpty()) {
            User user = new User();
            user.setUsername("testuser");
            user.setEmail("testuser@test.local");
            user.setPasswordHash(passwordEncoder.encode("password123"));
            user.setRole(Role.USER);
            user.setStatus("ACTIVE");
            userRepository.save(user);
        }
    }

    @Test
    void oidcDiscoveryEndpointIsReachable() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuer").value("https://auth.test.local"))
            .andExpect(jsonPath("$.authorization_endpoint").exists())
            .andExpect(jsonPath("$.token_endpoint").exists())
            .andExpect(jsonPath("$.jwks_uri").exists())
            .andExpect(jsonPath("$.userinfo_endpoint").exists());
    }

    @Test
    void jwksEndpointReturnsPublicKey() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kid").value("auth-service-v1"))
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
    }

    @Test
    void authorizeEndpointRedirectsToLoginWhenUnauthenticated() throws Exception {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("redirect_uri", "https://app.test.local/callback")
                .param("scope", "openid profile email")
                .param("state", "test-state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login**"));
    }

    @Test
    void fullAuthCodeFlowIssuesTokens() throws Exception {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // Step 1: GET /oauth2/authorize → 302 to /login
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("redirect_uri", "https://app.test.local/callback")
                .param("scope", "openid profile email")
                .param("state", "test-state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256"))
            .andExpect(status().is3xxRedirection())
            .andReturn();

        MockHttpSession session = (MockHttpSession) authorizeResult.getRequest().getSession();

        // Step 2: POST /login with credentials
        MvcResult loginResult = mockMvc.perform(post("/login")
                .param("username", "testuser")
                .param("password", "password123")
                .session(session)
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andReturn();

        session = (MockHttpSession) loginResult.getRequest().getSession();
        String loginRedirect = loginResult.getResponse().getRedirectedUrl();
        assertThat(loginRedirect).isNotNull();

        // Step 3: Follow redirect back to /oauth2/authorize → 302 to redirect_uri?code=...
        MvcResult codeResult = mockMvc.perform(get(loginRedirect).session(session))
            .andExpect(status().is3xxRedirection())
            .andReturn();

        String callbackUrl = codeResult.getResponse().getRedirectedUrl();
        assertThat(callbackUrl).isNotNull().contains("code=").contains("state=test-state");

        String code = extractParam(callbackUrl, "code");

        // Step 4: POST /oauth2/token — exchange code for tokens
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", "https://app.test.local/callback")
                .param("code_verifier", codeVerifier)
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                    "test-client:test-secret".getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.id_token").exists())
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andReturn();

        String responseBody = tokenResult.getResponse().getContentAsString();
        String accessToken = extractJsonField(responseBody, "access_token");
        String idToken = extractJsonField(responseBody, "id_token");
        assertThat(accessToken).isNotEmpty();

        // Verify role claim in id_token payload
        String idTokenPayload = new String(
            Base64.getUrlDecoder().decode(idToken.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(idTokenPayload).contains("\"role\"");

        // Step 5: GET /userinfo with access token
        mockMvc.perform(get("/userinfo")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sub").value("testuser"))
            .andExpect(jsonPath("$.email").value("testuser@test.local"))
            .andExpect(jsonPath("$.preferred_username").value("testuser"));
    }

    @Test
    void tokenEndpointRejectsInvalidCode() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", "invalid-code")
                .param("redirect_uri", "https://app.test.local/callback")
                .param("code_verifier", "some-verifier")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                    "test-client:test-secret".getBytes(StandardCharsets.UTF_8))))
            .andExpect(status().isBadRequest());
    }

    @Test
    void adminApiRequiresBearerToken() throws Exception {
        mockMvc.perform(get("/api/v1/users"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void loginPageIsRendered() throws Exception {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith("text/html"));
    }

    @Test
    void oidcDiscoveryAdvertisesLogoutEndpoint() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.end_session_endpoint").value(
                org.hamcrest.Matchers.endsWith("/connect/logout")));
    }

    // --- helpers ---

    private static String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String generateCodeChallenge(String codeVerifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String extractParam(String url, String param) {
        for (String part : url.split("[?&]")) {
            if (part.startsWith(param + "=")) {
                return part.substring(param.length() + 1);
            }
        }
        throw new IllegalArgumentException("Param " + param + " not found in: " + url);
    }

    private static String extractJsonField(String json, String field) {
        String key = "\"" + field + "\":\"";
        int start = json.indexOf(key);
        if (start == -1) throw new IllegalArgumentException("Field " + field + " not found in: " + json);
        start += key.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }
}
