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
 * Verifies Flyway V6 (docs/060-network-monitoring.md §7.5): on an existing database the
 * seeded furchert-ch row gains client_credentials and netmon:read exactly once. Each test
 * resets the row to its pre-V6 (legacy) shape and replays the migration script inside a
 * rolled-back transaction, so the shared Testcontainers database stays untouched.
 */
@Transactional
class FurchertChClientCredentialsMigrationTest extends AbstractIntegrationTest {

    private static final String V6_SCRIPT = "db/migration/V6__furchert_ch_client_credentials.sql";

    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    DataSource dataSource;

    @BeforeEach
    void resetFurchertChRowToLegacyShape() {
        // The legacy seeder wrote exactly these values before V6 (SAS comma lists, no spaces).
        int updated = jdbcTemplate.update(
                "UPDATE oauth2_registered_client "
                        + "SET authorization_grant_types = 'refresh_token,authorization_code', "
                        + "scopes = 'openid,profile,email' "
                        + "WHERE client_id = 'furchert-ch'");
        assertThat(updated).as("seeded furchert-ch row").isEqualTo(1);
    }

    @Test
    void v6IsRecordedAsSuccessfullyApplied() {
        Boolean success = jdbcTemplate.queryForObject(
                "SELECT success FROM flyway_schema_history_auth WHERE version = '6'", Boolean.class);
        assertThat(success).isTrue();
    }

    @Test
    void migrationAppendsGrantAndScopeExactlyOnceAndKeepsExistingValues() {
        runV6();

        Map<String, Object> row = furchertChRow();
        assertThat(split(row.get("authorization_grant_types")))
                .containsExactlyInAnyOrder("authorization_code", "refresh_token", "client_credentials");
        assertThat(split(row.get("scopes")))
                .containsExactlyInAnyOrder("openid", "profile", "email", "netmon:read");
    }

    @Test
    void rerunningMigrationIsNoOp() {
        runV6();
        Map<String, Object> afterFirstRun = furchertChRow();

        runV6();

        assertThat(furchertChRow()).isEqualTo(afterFirstRun);
    }

    @Test
    void migrationDoesNotTouchOtherClients() {
        Map<String, Object> before = jdbcTemplate.queryForMap(
                "SELECT authorization_grant_types, scopes FROM oauth2_registered_client WHERE client_id = 'test-client'");

        runV6();

        assertThat(jdbcTemplate.queryForMap(
                "SELECT authorization_grant_types, scopes FROM oauth2_registered_client WHERE client_id = 'test-client'"))
                .isEqualTo(before);
    }

    @Test
    void migrationIsNoOpWhenFurchertChRowIsAbsent() {
        // Fresh-database case: V6 runs before StaticClientSeeder has created the row.
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = 'furchert-ch'");

        runV6();

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = 'furchert-ch'", Integer.class);
        assertThat(count).isZero();
    }

    private void runV6() {
        // DatabasePopulatorUtils obtains the connection via DataSourceUtils, so the script
        // joins the test transaction and is rolled back with it.
        new ResourceDatabasePopulator(new ClassPathResource(V6_SCRIPT)).execute(dataSource);
    }

    private Map<String, Object> furchertChRow() {
        return jdbcTemplate.queryForMap(
                "SELECT authorization_grant_types, scopes FROM oauth2_registered_client WHERE client_id = 'furchert-ch'");
    }

    private static List<String> split(Object commaList) {
        return Arrays.asList(((String) commaList).split(","));
    }
}
