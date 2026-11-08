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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies Flyway V10 (docs/100-web-analytics.md §11, #142): on an existing database the
 * furchert-ch row gains analytics:write and analytics:read exactly once and keeps every other
 * value. Each test resets the row to its pre-V10 shape and replays the migration script inside a
 * rolled-back transaction, so the shared Testcontainers database stays untouched.
 */
@Transactional
class FurchertChAnalyticsScopesMigrationTest extends AbstractIntegrationTest {

    private static final String V10_SCRIPT = "db/migration/V10__furchert_ch_analytics_scopes.sql";
    private static final String PRE_V10_GRANTS = "refresh_token,authorization_code,client_credentials";

    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    DataSource dataSource;

    @BeforeEach
    void resetFurchertChRowToPreV10Shape() {
        // The row as V6 left it in production (SAS comma lists, no spaces).
        int updated = jdbcTemplate.update(
                "UPDATE oauth2_registered_client "
                        + "SET authorization_grant_types = ?, scopes = 'openid,profile,email,netmon:read' "
                        + "WHERE client_id = 'furchert-ch'", PRE_V10_GRANTS);
        assertThat(updated).as("seeded furchert-ch row").isEqualTo(1);
    }

    @Test
    void v10IsRecordedAsSuccessfullyApplied() {
        Boolean success = jdbcTemplate.queryForObject(
                "SELECT success FROM flyway_schema_history_auth WHERE version = '10'", Boolean.class);
        assertThat(success).isTrue();
    }

    @Test
    void migrationAppendsBothScopesExactlyOnceAndKeepsExistingValues() {
        runV10();

        Map<String, Object> row = furchertChRow();
        assertThat(split(row.get("scopes"))).containsExactlyInAnyOrder(
                "openid", "profile", "email", "netmon:read", "analytics:write", "analytics:read");
        assertThat(row.get("authorization_grant_types")).isEqualTo(PRE_V10_GRANTS);
    }

    @Test
    void rerunningMigrationIsNoOp() {
        runV10();
        Map<String, Object> afterFirstRun = furchertChRow();

        runV10();

        assertThat(furchertChRow()).isEqualTo(afterFirstRun);
    }

    @Test
    void migrationAddsOnlyTheMissingScope() {
        jdbcTemplate.update("UPDATE oauth2_registered_client SET scopes = 'openid,analytics:read,profile' "
                + "WHERE client_id = 'furchert-ch'");

        runV10();

        assertThat(split(furchertChRow().get("scopes")))
                .containsExactlyInAnyOrder("openid", "analytics:read", "profile", "analytics:write");
    }

    @Test
    void migrationDoesNotTouchOtherClients() {
        String sql = "SELECT client_id, authorization_grant_types, scopes FROM oauth2_registered_client "
                + "WHERE client_id IN ('test-client', 'device-service') ORDER BY client_id";
        List<Map<String, Object>> before = jdbcTemplate.queryForList(sql);
        assertThat(before).hasSize(2);

        runV10();

        assertThat(jdbcTemplate.queryForList(sql)).isEqualTo(before);
    }

    @Test
    void migrationIsNoOpWhenFurchertChRowIsAbsent() {
        // Fresh-database case: V10 runs before StaticClientSeeder has created the row.
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = 'furchert-ch'");

        runV10();

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = 'furchert-ch'", Integer.class);
        assertThat(count).isZero();
    }

    private void runV10() {
        // DatabasePopulatorUtils obtains the connection via DataSourceUtils, so the script
        // joins the test transaction and is rolled back with it.
        new ResourceDatabasePopulator(new ClassPathResource(V10_SCRIPT)).execute(dataSource);
    }

    private Map<String, Object> furchertChRow() {
        return jdbcTemplate.queryForMap(
                "SELECT authorization_grant_types, scopes FROM oauth2_registered_client WHERE client_id = 'furchert-ch'");
    }

    private static List<String> split(Object commaList) {
        return Arrays.asList(((String) commaList).split(","));
    }
}
