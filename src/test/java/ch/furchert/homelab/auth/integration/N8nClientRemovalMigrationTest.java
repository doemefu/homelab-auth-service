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
 * V9 removes the n8n SSO client with its authorizations and consents and nothing else. The test
 * configuration still seeds an {@code n8n} client (a generic SSO stand-in, seeded after Flyway), which gives
 * this test a real row with the seeder's id; {@code @Transactional} rolls every change back.
 */
@Transactional
class N8nClientRemovalMigrationTest extends AbstractIntegrationTest {

    private static final String V9_SCRIPT = "db/migration/V9__remove_n8n_client.sql";

    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    DataSource dataSource;

    private String n8nId;
    private String otherId;

    @BeforeEach
    void childRows() {
        n8nId = idOf("n8n");
        otherId = idOf("test-client");
        for (String clientId : new String[] {n8nId, otherId}) {
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

    private void runV9() {
        new ResourceDatabasePopulator(new ClassPathResource(V9_SCRIPT)).execute(dataSource);
    }

    @Test
    void v9IsRecordedAsSuccessfullyApplied() {
        assertThat(jdbcTemplate.queryForObject(
                "SELECT success FROM flyway_schema_history_auth WHERE version = '9'", Boolean.class)).isTrue();
    }

    @Test
    void removesTheN8nClientWithItsAuthorizationsAndConsentsOnly() {
        runV9();

        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'n8n'")).isZero();
        assertThat(count("SELECT count(*) FROM oauth2_authorization WHERE registered_client_id = ?", n8nId)).isZero();
        assertThat(count("SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ?", n8nId))
                .isZero();
        // Only this test's own rows of the other client are checked: the shared test database may hold more.
        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", otherId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization WHERE id = ?", "auth-" + otherId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ? "
                + "AND principal_name = 'someone'", otherId)).isEqualTo(1);
    }

    @Test
    void runningItAgainIsHarmless() {
        runV9();
        runV9();   // must not fail on a database where the row is already gone

        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'n8n'")).isZero();
        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", otherId)).isEqualTo(1);
    }

    @Test
    void aDeviceClientWithTheSameIdIsKeptWithItsRows() {
        jdbcTemplate.update("UPDATE oauth2_registered_client SET client_kind = 'device' WHERE id = ?", n8nId);

        runV9();

        assertThat(count("SELECT count(*) FROM oauth2_registered_client WHERE id = ?", n8nId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization WHERE id = ?", "auth-" + n8nId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM oauth2_authorization_consent WHERE registered_client_id = ? "
                + "AND principal_name = 'someone'", n8nId)).isEqualTo(1);
    }
}
