package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import ch.furchert.homelab.auth.dto.ResetPasswordRequest;
import ch.furchert.homelab.auth.entity.Role;
import ch.furchert.homelab.auth.repository.UserRepository;
import ch.furchert.homelab.auth.service.UserService;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_CALLBACK;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_RESOURCE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SCOPE;
import static ch.furchert.homelab.auth.integration.AuthCodeFlow.HUB_SECRET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Gate G4b of docs/080 §4.5 (consent persistence, #107): a consent decision is stored with timestamps,
 * survives a restart of the application context, and every revocation path removes it so that the
 * consent page is shown again. Also runs the binding incident revocation SQL and the binding
 * client-removal SQL of docs/080 §4.6 verbatim.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class McpHubConsentPersistenceGateTest extends AbstractIntegrationTest {

    // Copy of the binding L4 revocation SQL (docs/080 §4.6) — keep byte-identical; the infrastructure
    // runbook and DEPLOYMENT.md copy it too.
    static final String L4_REVOCATION_SQL = """
            BEGIN;
            DELETE FROM oauth2_authorization_consent
             WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
            DELETE FROM oauth2_authorization
             WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
            COMMIT;
            """;

    // Copy of the binding client-removal SQL (docs/080 §4.6 "Disabling and removing the hub client") —
    // keep byte-identical; DEPLOYMENT.md and the infrastructure runbook copy it too.
    static final String CLIENT_REMOVAL_SQL = """
            BEGIN;
            DELETE FROM oauth2_authorization_consent
             WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
            DELETE FROM oauth2_authorization
             WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
            DELETE FROM oauth2_registered_client
             WHERE client_id = 'claude-mcp-hub';
            COMMIT;
            """;

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
    RegisteredClientRepository registeredClients;

    private AuthCodeFlow flow;

    @BeforeEach
    void setUp() {
        flow = new AuthCodeFlow(mockMvc, objectMapper, userRepository, passwordEncoder, jdbc, jwkSource);
        flow.createUser("hubowner", "password123", Role.USER);
    }

    private static AuthCodeFlow.Req hubReq() {
        return new AuthCodeFlow.Req(HUB, HUB_CALLBACK, HUB_SCOPE, HUB_RESOURCE);
    }

    @Test
    @Order(1)
    void approvedConsentIsStoredWithTimestamps() throws Exception {
        flow.forgetConsent(HUB, "hubowner");
        flow.hubTokens("hubowner", "password123");                 // consent page shown and approved
        Map<String, Object> row = jdbc.queryForMap("""
                SELECT c.authorities, c.created_at, c.updated_at FROM oauth2_authorization_consent c
                JOIN oauth2_registered_client r ON r.id = c.registered_client_id
                WHERE r.client_id = ? AND c.principal_name = ?""", HUB, "hubowner");
        assertThat(((String) row.get("authorities")).split(","))
                .containsExactlyInAnyOrder("SCOPE_mail:read", "SCOPE_calendar:read");
        assertThat(row.get("created_at")).isNotNull();
        assertThat(row.get("updated_at")).isNotNull();
    }

    @Test
    @Order(2)
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.BEFORE_METHOD)
    void consentSurvivesARestartOfTheApplicationContext() throws Exception {
        // Fresh application context (in-memory state gone), same database: no consent page, direct code.
        MvcResult r = flow.authorizeAs(hubReq(), "hubowner", "password123", AuthCodeFlow.pkce());
        assertThat(r.getResponse().getStatus()).isEqualTo(302);
        assertThat(AuthCodeFlow.param(r.getResponse().getRedirectedUrl(), "code")).isNotBlank();
    }

    @Test
    @Order(3)
    void passwordResetRemovesConsentAndConsentPageReturns() throws Exception {
        long id = userRepository.findByUsername("hubowner").orElseThrow().getId();
        userService.resetPassword(id, new ResetPasswordRequest(null, "password123"), "admin", true);
        assertThat(flow.consentRows(HUB, "hubowner")).isZero();
        MvcResult r = flow.authorizeAs(hubReq(), "hubowner", "password123", AuthCodeFlow.pkce());
        assertThat(r.getResponse().getStatus()).isEqualTo(200);   // consent page again
    }

    @Test
    @Order(4)
    void l4RevocationSqlRemovesConsentAndConsentPageReturns() throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        assertThat(flow.consentRows(HUB, "hubowner")).isOne();
        // Executed verbatim as one multi-statement string incl. BEGIN/COMMIT (PostgreSQL simple query).
        jdbc.execute(L4_REVOCATION_SQL);
        assertThat(flow.consentRows(HUB, "hubowner")).isZero();
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE)
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"));
        MvcResult r = flow.authorizeAs(hubReq(), "hubowner", "password123", AuthCodeFlow.pkce());
        assertThat(r.getResponse().getStatus()).isEqualTo(200);   // consent page again
    }

    @Test
    @Order(5)
    void denyingEveryScopeStoresNothing() throws Exception {
        flow.forgetConsent(HUB, "hubowner");
        MvcResult consent = flow.authorizeAs(hubReq(), "hubowner", "password123", AuthCodeFlow.pkce());
        String location = flow.approveConsent(consent, HUB).getResponse().getRedirectedUrl();   // no scope ticked
        assertThat(AuthCodeFlow.param(location, "error")).isEqualTo("access_denied");
        assertThat(flow.consentRows(HUB, "hubowner")).isZero();
    }

    @Test
    @Order(6)
    // Removes the hub row from the shared database: the next test class gets a fresh context, whose
    // seeder seeds the hub client again (same deterministic id).
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void clientRemovalSqlRemovesTheClientWithItsConsentsAndAuthorizations() throws Exception {
        AuthCodeFlow.TokenPair t = flow.hubTokens("hubowner", "password123");
        assertThat(flow.consentRows(HUB, "hubowner")).isOne();
        jdbc.execute(CLIENT_REMOVAL_SQL);   // verbatim, one transaction
        assertThat(registeredClients.findByClientId(HUB)).isNull();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization_consent WHERE principal_name = 'hubowner'",
                Integer.class)).isZero();   // no consent row of the removed client left behind (loader would fail)
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization a WHERE a.principal_name = 'hubowner' "
                        + "AND NOT EXISTS (SELECT 1 FROM oauth2_registered_client r WHERE r.id = a.registered_client_id)",
                Integer.class)).isZero();
        flow.refreshPost(HUB, HUB_SECRET, t.refreshToken(), HUB_RESOURCE)
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
    }
}
