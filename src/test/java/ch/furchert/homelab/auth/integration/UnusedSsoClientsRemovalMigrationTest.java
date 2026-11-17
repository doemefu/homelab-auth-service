package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V11 removes the grafana and homeassistant SSO clients with their authorizations and consents and nothing else
 * (#154). The test configuration seeds {@code homeassistant} as a generic SSO stand-in (after Flyway); the seeded
 * {@code n8n} stand-in is renamed to {@code grafana} inside the test, so both ids have a real row with the
 * seeder's id. {@code @Transactional} rolls every change back.
 */
@Transactional
class UnusedSsoClientsRemovalMigrationTest extends AbstractIntegrationTest {

    private static final String V11_SCRIPT = "db/migration/V11__remove_unused_sso_clients.sql";

    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    DataSource dataSource;

    private String haId;
    private String grafanaId;
    private String otherId;

    @BeforeEach
    void childRows() {
        haId = idOf("homeassistant");
        grafanaId = idOf("n8n");
        jdbcTemplate.update("UPDATE oauth2_registered_client SET client_id = 'grafana' WHERE id = ?", grafanaId);
        otherId = idOf("test-client");
        for (String clientId : new String[] {haId, grafanaId, otherId}) {
            jdbcTemplate.update("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, "
                    + "authorization_grant_type) VALUES (?, ?, 'someone', 'authorization_code')",
                    "auth-" + clientId, clientId);
            jdbcTemplate.update("INSERT INTO oauth2_authorization_consent (registered_client_id, principal_name, "
                    + "authorities) VALUES (?, 'someone', 'SCOPE_openid')", clientId);
        }
    }

    private String idOf(String clientId) {
        return jdbcTemplate.queryForObject("SELECT id FROM oauth2_registered_client WHERE client_id = ?",
                String.class, clientId);
    }

    private int count(String sql, Object... args) {
        Integer n = jdbcTemplate.queryForObject(sql, Integer.class, args);
        return n == null ? 0 : n;
    }

    private void runV11() {
        new ResourceDatabasePopulator(new ClassPathResource(V11_SCRIPT)).execute(dataSource);
    }

    @Test
    void v11IsRecordedAsSuccessfullyApplied() {
        assertThat(jdbcTemplate.queryForObject(
                "SELECT success FROM flyway_schema_history_auth WHERE version = '11'", Boolean.class)).isTrue();
    }

    @Test
    void removesBothClientsWithTheirAuthorizationsAndConsentsOnly() {
        runV11();

        for (String id : new String[] {haId, grafanaId}) {
            assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", id)).isZero();
            assertThat(count("SELECT count(*) FROM oauth2_authorization WHERE registered_client_id = ?", id)).isZero();
            assertThat(count("SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ?", id))
                    .isZero();
        }
        // Only this test's own rows of the other client are checked: the shared test database may hold more.
        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", otherId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization WHERE id = ?", "auth-" + otherId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ? "
                + "AND principal_name = 'someone'", otherId)).isEqualTo(1);
    }

    @Test
    void runningItAgainIsHarmless() {
        runV11();
        runV11();   // must not fail on a database where the rows are already gone

        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE client_id IN ('grafana', 'homeassistant')"))
                .isZero();
        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", otherId)).isEqualTo(1);
    }

    @Test
    void aDeviceClientWithTheSameIdIsKeptWithItsRows() {
        jdbcTemplate.update("UPDATE oauth2_registered_client SET client_kind = 'device' WHERE id = ?", haId);

        runV11();

        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", haId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization WHERE id = ?", "auth-" + haId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ? "
                + "AND principal_name = 'someone'", haId)).isEqualTo(1);
    }
}
