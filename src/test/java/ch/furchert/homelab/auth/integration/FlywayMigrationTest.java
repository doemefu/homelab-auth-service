package ch.furchert.homelab.auth.integration;

import ch.furchert.homelab.auth.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

class FlywayMigrationTest extends AbstractIntegrationTest {

    @Autowired
    JdbcTemplate jdbcTemplate;

    @ParameterizedTest
    @ValueSource(strings = {"oauth2_authorization", "oauth2_authorization_consent", "oauth2_registered_client"})
    void tableExists(String tableName) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.tables " +
                        "WHERE table_schema = 'public' AND table_name = ?", Integer.class, tableName);
        assertThat(count).isEqualTo(1);
    }

    @Test
    void oauth2RegisteredClientHasClientKindColumnWithSsoDefault() {
        // The V5 migration adds client_kind VARCHAR(20) NOT NULL DEFAULT 'sso'.
        Integer columnCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.columns " +
                        "WHERE table_schema = 'public' AND table_name = 'oauth2_registered_client' " +
                        "AND column_name = 'client_kind'", Integer.class);
        assertThat(columnCount).isEqualTo(1);

        String columnDefault = jdbcTemplate.queryForObject(
                "SELECT column_default FROM information_schema.columns " +
                        "WHERE table_schema = 'public' AND table_name = 'oauth2_registered_client' " +
                        "AND column_name = 'client_kind'", String.class);
        assertThat(columnDefault).contains("sso");
    }
}
