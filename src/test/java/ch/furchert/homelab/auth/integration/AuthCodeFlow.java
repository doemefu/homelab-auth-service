package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.entity.User;
import ch.furchert.homelab.auth.repository.UserRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc helper for authorization-code flows against the real application context (#107 gate tests):
 * authorize, login, consent, token exchange and refresh, plus JWT decoding.
 */
final class AuthCodeFlow {

    static final String HUB = "claude-mcp-hub";
    static final String HUB_SECRET = "hub-secret";
    static final String HUB_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
    static final String HUB_RESOURCE = "https://mcp.furchert.ch/mcp";
    static final String HUB_SCOPE = "mail:read calendar:read";

    record Req(String clientId, String redirectUri, String scope, String resource) {
    }

    record Pkce(String verifier, String challenge) {
    }

    record TokenPair(String accessToken, String refreshToken) {
    }

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JdbcTemplate jdbcTemplate;

    AuthCodeFlow(MockMvc mockMvc, ObjectMapper objectMapper, UserRepository userRepository,
                 PasswordEncoder passwordEncoder, JdbcTemplate jdbcTemplate) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jdbcTemplate = jdbcTemplate;
    }

    MvcResult authorizeAnonymous(Req r, Pkce p) throws Exception {
        return mockMvc.perform(authorize(r, p)).andReturn();
    }

    MvcResult authorizeAs(Req r, String username, String password, Pkce p) throws Exception {
        MvcResult first = mockMvc.perform(authorize(r, p)).andExpect(status().is3xxRedirection()).andReturn();
        MockHttpSession session = (MockHttpSession) first.getRequest().getSession();
        MvcResult login = mockMvc.perform(post("/login").param("username", username).param("password", password)
                        .session(session).with(csrf()))
                .andExpect(status().is3xxRedirection()).andReturn();
        session = (MockHttpSession) login.getRequest().getSession();
        // Replay instead of following the saved-request redirect (MockMvc re-encodes the query, see OidcFlowIntegrationTest).
        return mockMvc.perform(authorize(r, p).session(session)).andReturn();
    }

    MvcResult approveConsent(MvcResult consentPage, String clientId, String... scopes) throws Exception {
        String state = hiddenInput(consentPage.getResponse().getContentAsString(), "state");
        MockHttpServletRequestBuilder b = post("/oauth2/authorize")
                .param("client_id", clientId).param("state", state)
                .session((MockHttpSession) consentPage.getRequest().getSession())
                .with(csrf());
        for (String s : scopes) {
            b.param("scope", s);
        }
        return mockMvc.perform(b).andExpect(status().is3xxRedirection()).andReturn();
    }

    static MockHttpServletRequestBuilder authorize(Req r, Pkce p) {
        MockHttpServletRequestBuilder b = get("/oauth2/authorize")
                .param("response_type", "code").param("client_id", r.clientId())
                .param("redirect_uri", r.redirectUri()).param("scope", r.scope())
                .param("state", "test-state").param("code_challenge", p.challenge())
                .param("code_challenge_method", "S256");
        StringBuilder qs = new StringBuilder("response_type=code&client_id=").append(enc(r.clientId()))
                .append("&redirect_uri=").append(enc(r.redirectUri())).append("&scope=").append(enc(r.scope()))
                .append("&state=test-state&code_challenge=").append(p.challenge()).append("&code_challenge_method=S256");
        if (r.resource() != null) {
            b.param("resource", r.resource());
            qs.append("&resource=").append(enc(r.resource()));
        }
        String query = qs.toString();
        return b.with(req -> {
            req.setQueryString(query);
            return req;
        });
    }

    ResultActions exchangePost(String clientId, String secret, String code, String redirectUri, Pkce p,
                               String resource) throws Exception {
        MockHttpServletRequestBuilder b = post("/oauth2/token")
                .param("grant_type", "authorization_code").param("code", code)
                .param("redirect_uri", redirectUri).param("code_verifier", p.verifier())
                .param("client_id", clientId).param("client_secret", secret);
        if (resource != null) {
            b.param("resource", resource);
        }
        return mockMvc.perform(b);
    }

    ResultActions exchangeBasic(String clientId, String secret, String code, String redirectUri, Pkce p,
                                String resource) throws Exception {
        MockHttpServletRequestBuilder b = post("/oauth2/token")
                .param("grant_type", "authorization_code").param("code", code)
                .param("redirect_uri", redirectUri).param("code_verifier", p.verifier())
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        if (resource != null) {
            b.param("resource", resource);
        }
        return mockMvc.perform(b);
    }

    ResultActions refreshPost(String clientId, String secret, String refreshToken, String resource) throws Exception {
        MockHttpServletRequestBuilder b = post("/oauth2/token")
                .param("grant_type", "refresh_token").param("refresh_token", refreshToken)
                .param("client_id", clientId).param("client_secret", secret);
        if (resource != null) {
            b.param("resource", resource);
        }
        return mockMvc.perform(b);
    }

    String hubCode(Req r, String username, String password, Pkce p) throws Exception {
        MvcResult afterLogin = authorizeAs(r, username, password, p);
        // Consent is remembered: the page appears only when this user has no stored consent yet;
        // otherwise the code comes directly. Never call approveConsent unconditionally.
        String location = afterLogin.getResponse().getStatus() == 200
                ? approveConsent(afterLogin, HUB, "mail:read", "calendar:read").getResponse().getRedirectedUrl()
                : afterLogin.getResponse().getRedirectedUrl();
        return param(location, "code");
    }

    TokenPair hubTokens(String username, String password) throws Exception {
        Pkce p = pkce();
        String code = hubCode(new Req(HUB, HUB_CALLBACK, HUB_SCOPE, HUB_RESOURCE), username, password, p);
        JsonNode body = json(exchangePost(HUB, HUB_SECRET, code, HUB_CALLBACK, p, HUB_RESOURCE)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id_token").doesNotExist())   // G1: no ID token for this client
                .andReturn());
        return new TokenPair(body.get("access_token").asString(), body.get("refresh_token").asString());
    }

    JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    void createUser(String username, String password, Role role) {
        if (userRepository.findByUsername(username).isEmpty()) {
            User user = new User();
            user.setUsername(username);
            user.setEmail(username + "@test.local");
            user.setPasswordHash(passwordEncoder.encode(password));
            user.setRole(role);
            user.setStatus("ACTIVE");
            userRepository.save(user);
        }
    }

    void forgetConsent(String clientId, String username) {
        jdbcTemplate.update("DELETE FROM oauth2_authorization_consent WHERE principal_name = ? AND registered_client_id = "
                + "(SELECT id FROM oauth2_registered_client WHERE client_id = ?)", username, clientId);
    }

    int consentRows(String clientId, String username) {
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM oauth2_authorization_consent c "
                + "JOIN oauth2_registered_client r ON r.id = c.registered_client_id "
                + "WHERE r.client_id = ? AND c.principal_name = ?", Integer.class, clientId, username);
        return count == null ? 0 : count;
    }

    static Map<String, Object> header(String jwt) {
        return decodePart(jwt, 0);
    }

    static Map<String, Object> payload(String jwt) {
        return decodePart(jwt, 1);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodePart(String jwt, int index) {
        byte[] bytes = Base64.getUrlDecoder().decode(jwt.split("\\.")[index]);
        return new ObjectMapper().readValue(bytes, Map.class);
    }

    /** Value of a query parameter of a redirect URL, URL-decoded; null when absent. */
    static String param(String url, String name) {
        if (url == null) {
            return null;
        }
        for (String part : url.split("[?&]")) {
            if (part.startsWith(name + "=")) {
                return URLDecoder.decode(part.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    static String hiddenInput(String html, String name) {
        Matcher m = Pattern.compile("name=\"" + Pattern.quote(name) + "\"\\s+value=\"([^\"]*)\"").matcher(html);
        if (!m.find()) {
            throw new AssertionError("hidden input '" + name + "' not found in consent page");
        }
        return m.group(1);
    }

    static Pkce pkce() throws Exception {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
