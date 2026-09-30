package ch.furchert.homelab.auth.security;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Consent store of the IdP (#107): JDBC-backed, timestamps from Flyway V8, one audit line per decision
 * without the username. Runs against the real PostgreSQL schema.
 */
@ExtendWith(OutputCaptureExtension.class)
class AuditingAuthorizationConsentServiceTest extends AbstractIntegrationTest {

    private static final String PRINCIPAL = "audit-probe";

    @Autowired
    OAuth2AuthorizationConsentService consents;
    @Autowired
    RegisteredClientRepository clients;
    @Autowired
    JdbcTemplate jdbc;

    @BeforeEach
    void cleanUp() {
        jdbc.update("DELETE FROM oauth2_authorization_consent WHERE principal_name = ?", PRINCIPAL);
    }

    @Test
    void firstSaveInsertsWithBothTimestamps(CapturedOutput out) {
        RegisteredClient hub = clients.findByClientId("claude-mcp-hub");
        consents.save(OAuth2AuthorizationConsent.withId(hub.getId(), PRINCIPAL).scope("mail:read").build());
        Map<String, Object> row = row(hub.getId());
        assertThat(row.get("authorities")).isEqualTo("SCOPE_mail:read");
        assertThat(row.get("created_at")).isNotNull();
        assertThat(row.get("updated_at")).isNotNull();
        assertThat(out.getOut()).contains("Consent saved: client='claude-mcp-hub'").contains("mail:read")
                .doesNotContain(PRINCIPAL);
    }

    @Test
    void secondSaveKeepsCreatedAtAndAdvancesUpdatedAt() throws Exception {
        RegisteredClient hub = clients.findByClientId("claude-mcp-hub");
        consents.save(OAuth2AuthorizationConsent.withId(hub.getId(), PRINCIPAL).scope("mail:read").build());
        Instant created = instant(row(hub.getId()).get("created_at"));
        Thread.sleep(20);   // now() is the transaction start time; separate transactions differ
        consents.save(OAuth2AuthorizationConsent.withId(hub.getId(), PRINCIPAL)
                .scope("mail:read").scope("calendar:read").build());
        Map<String, Object> row = row(hub.getId());
        assertThat(instant(row.get("created_at"))).isEqualTo(created);
        assertThat(instant(row.get("updated_at"))).isAfter(created);
        assertThat((String) row.get("authorities")).contains("SCOPE_calendar:read");
    }

    @Test
    void removeDeletesRowAndLogsWithoutUsername(CapturedOutput out) {
        RegisteredClient hub = clients.findByClientId("claude-mcp-hub");
        OAuth2AuthorizationConsent c = OAuth2AuthorizationConsent.withId(hub.getId(), PRINCIPAL).scope("mail:read").build();
        consents.save(c);
        consents.remove(c);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_authorization_consent WHERE principal_name = ?",
                Integer.class, PRINCIPAL)).isZero();
        assertThat(out.getOut()).contains("Consent removed: client='claude-mcp-hub'").doesNotContain(PRINCIPAL);
    }

    @Test
    void theIdpUsesTheJdbcBackedService(@Autowired OAuth2AuthorizationConsentService bean) {
        assertThat(AopUtils.getTargetClass(bean)).isEqualTo(AuditingAuthorizationConsentService.class);
    }

    private Map<String, Object> row(String registeredClientId) {
        return jdbc.queryForMap("SELECT authorities, created_at, updated_at FROM oauth2_authorization_consent "
                + "WHERE registered_client_id = ? AND principal_name = ?", registeredClientId, PRINCIPAL);
    }

    private static Instant instant(Object value) {
        if (value instanceof Timestamp ts) {
            return ts.toInstant();
        }
        return ((OffsetDateTime) value).toInstant();
    }
}
