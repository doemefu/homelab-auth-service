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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

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
    @Autowired ObjectMapper objectMapper;

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
    void registeredClientHasExpectedScopes(@Autowired org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository clientRepo) {
        var client = clientRepo.findByClientId("test-client");
        assertThat(client).isNotNull();
        assertThat(client.getScopes())
            .as("Registered client 'test-client' scopes")
            .containsExactlyInAnyOrder("openid", "profile", "email");
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

        // Spring AS reads OAuth2 params via getQueryParameters() which requires
        // keys to appear in request.getQueryString(). MockMvc's .param() populates
        // the parameter map (with correctly decoded values) but not the query string.
        // We use .param() for decoded values + a RequestPostProcessor to set the
        // raw query string so Spring AS can find the parameter keys.
        mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("redirect_uri", "https://app.test.local/callback")
                .param("scope", "openid profile email")
                .param("state", "test-state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256")
                .with(request -> {
                    request.setQueryString(buildQueryString(codeChallenge));
                    return request;
                }))
            .andExpect(status().is3xxRedirection())
            .andExpect(result -> {
                String redirectUrl = result.getResponse().getRedirectedUrl();
                assertThat(redirectUrl).isNotNull();
                assertThat(redirectUrl).contains("/login");
            });
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
                .param("code_challenge_method", "S256")
                .with(request -> {
                    request.setQueryString(buildQueryString(codeChallenge));
                    return request;
                }))
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

        // Step 3: Replay authorize request with authenticated session.
        // We cannot simply GET the loginRedirect URL because MockMvc re-encodes
        // query params (%20 / +), causing Spring AS scope validation to fail.
        MvcResult codeResult = mockMvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("redirect_uri", "https://app.test.local/callback")
                .param("scope", "openid profile email")
                .param("state", "test-state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256")
                .session(session)
                .with(request -> {
                    request.setQueryString(buildQueryString(codeChallenge));
                    return request;
                }))
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

        JsonNode tokenResponse = objectMapper.readTree(
                tokenResult.getResponse().getContentAsString());
        String accessToken = tokenResponse.get("access_token").asText();
        String idToken = tokenResponse.get("id_token").asText();
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

    private static String buildQueryString(String codeChallenge) {
        // Raw query string for request.setQueryString(). Spring AS's
        // getQueryParameters() checks that each parameter key appears in
        // the query string before including it. The values here don't matter
        // as much — Spring AS reads values from the parameter map, not the
        // query string directly.
        return "response_type=code"
                + "&client_id=test-client"
                + "&redirect_uri=https://app.test.local/callback"
                + "&scope=openid+profile+email"
                + "&state=test-state"
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256";
    }

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

}
