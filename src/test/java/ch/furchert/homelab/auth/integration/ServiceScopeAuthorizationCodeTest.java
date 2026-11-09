package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * #143: service scopes are issued only through client_credentials. They are refused at the authorization
 * endpoint (invalid_scope redirect) and, for an authorization that holds one, at code exchange and refresh
 * (invalid_grant). Real filter chain and really signed tokens.
 */
class ServiceScopeAuthorizationCodeTest extends AbstractIntegrationTest {

    private static final String FC = "furchert-ch";
    private static final String FC_SECRET = "furchert-ch-secret";
    private static final String FC_CALLBACK = "https://furchert.test.local/api/auth/callback/furchert-ch";
    private static final String USER = "wa5-scope-user";
    private static final String PASSWORD = "password123";
    private static final String OIDC = "openid profile email";

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

    private AuthCodeFlow flow;

    @BeforeEach
    void setUp() {
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser(USER, PASSWORD, Role.USER);
        deleteAuthorizations();
    }

    @AfterEach
    void cleanUp() {
        deleteAuthorizations();
        jdbc.update("DELETE FROM users WHERE username = ?", USER);
    }

    private void deleteAuthorizations() {
        jdbc.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", USER);
    }

    @ParameterizedTest
    @ValueSource(strings = {"netmon:read", "analytics:write", "analytics:read"})
    void authorizeRefusesServiceScopeBeforeLogin(String scope) throws Exception {
        MvcResult r = flow.authorizeAnonymous(new AuthCodeFlow.Req(FC, FC_CALLBACK, "openid " + scope, null),
                AuthCodeFlow.pkce());

        assertRefusedRedirect(r, FC_CALLBACK);
    }

    @Test
    void authorizeRefusesServiceScopeAfterLogin() throws Exception {
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(FC, FC_CALLBACK, OIDC + " analytics:read", null),
                USER, PASSWORD, AuthCodeFlow.pkce());

        assertRefusedRedirect(r, FC_CALLBACK);
    }

    @Test
    void authorizeRefusesClientsAdminForDeviceService() throws Exception {
        String callback = "https://device.test.local/callback";
        MvcResult r = flow.authorizeAnonymous(new AuthCodeFlow.Req("device-service", callback,
                "openid clients:admin", null), AuthCodeFlow.pkce());

        assertRefusedRedirect(r, callback);
    }

    @Test
    void codeExchangeOfAnAuthorizationHoldingAServiceScopeIsRefused() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = code(p);
        assertThat(addServiceScopeToStoredAuthorization()).isOne();

        flow.exchangeBasic(FC, FC_SECRET, code, FC_CALLBACK, p, null)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void refreshOfAnAuthorizationHoldingAServiceScopeIsRefusedUnlessNarrowed() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        String code = code(p);
        JsonNode tokens = flow.json(flow.exchangeBasic(FC, FC_SECRET, code, FC_CALLBACK, p, null)
                .andExpect(status().isOk()).andReturn());
        // Control: an ordinary furchert-ch login token keeps its user claims.
        assertThat(AuthCodeFlow.payload(tokens.get("access_token").asString())).containsEntry("role", "USER");
        String refresh = tokens.get("refresh_token").asString();
        assertThat(addServiceScopeToStoredAuthorization()).isOne();

        // No scope parameter: SAS reuses every stored scope, including the service scope.
        flow.refreshBasic(FC, FC_SECRET, refresh, null)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.access_token").doesNotExist());

        // Narrowed to OIDC scopes: accepted, and the token holds no service scope.
        JsonNode narrowed = flow.json(flow.refreshBasic(FC, FC_SECRET, refresh, OIDC)
                .andExpect(status().isOk()).andReturn());
        Map<String, Object> claims = AuthCodeFlow.payload(narrowed.get("access_token").asString());
        assertThat(scopes(claims)).doesNotContain("netmon:read").contains("openid");
    }

    @Test
    void ordinaryLoginAndRefreshStillWork() throws Exception {
        AuthCodeFlow.Pkce p = AuthCodeFlow.pkce();
        JsonNode tokens = flow.json(flow.exchangeBasic(FC, FC_SECRET, code(p), FC_CALLBACK, p, null)
                .andExpect(status().isOk()).andExpect(jsonPath("$.id_token").exists()).andReturn());

        flow.refreshBasic(FC, FC_SECRET, tokens.get("refresh_token").asString(), null)
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").exists());
    }

    @Test
    void pushedAuthorizationRequestEndpointIsNotEnabled() throws Exception {
        // The validator chain is attached to the authorization endpoint only; PAR must stay off.
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pushed_authorization_request_endpoint").doesNotExist());
        MvcResult par = mockMvc.perform(post("/oauth2/par")
                        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                                (FC + ":" + FC_SECRET).getBytes(StandardCharsets.UTF_8)))
                        .param("response_type", "code").param("client_id", FC)
                        .param("redirect_uri", FC_CALLBACK).param("scope", "openid netmon:read"))
                .andReturn();
        assertThat(par.getResponse().getStatus()).isNotEqualTo(201);
        assertThat(par.getResponse().getContentAsString()).doesNotContain("request_uri");
    }

    private String code(AuthCodeFlow.Pkce p) throws Exception {
        MvcResult r = flow.authorizeAs(new AuthCodeFlow.Req(FC, FC_CALLBACK, OIDC, null), USER, PASSWORD, p);
        String code = AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code");
        assertThat(code).isNotBlank();
        return code;
    }

    /** Simulates an authorization stored before #143 that already holds a service scope. */
    private int addServiceScopeToStoredAuthorization() {
        return jdbc.update("UPDATE oauth2_authorization SET authorized_scopes = 'openid,profile,email,netmon:read' "
                + "WHERE principal_name = ? AND registered_client_id = "
                + "(SELECT id FROM oauth2_registered_client WHERE client_id = ?)", USER, FC);
    }

    private static void assertRefusedRedirect(MvcResult r, String callback) {
        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        String location = r.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(callback);
        assertThat(AuthCodeFlow.param(location, "error")).isEqualTo("invalid_scope");
        assertThat(AuthCodeFlow.param(location, "code")).isNull();
    }

    @SuppressWarnings("unchecked")
    private static List<String> scopes(Map<String, Object> claims) {
        Object scope = claims.get("scope");
        return scope instanceof List<?> list ? (List<String>) list : List.of(String.valueOf(scope).split(" "));
    }
}
