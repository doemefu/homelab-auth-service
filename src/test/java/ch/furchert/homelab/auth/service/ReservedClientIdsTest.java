package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservedClientIdsTest {

    private static final String EXISTS_SQL =
            "SELECT EXISTS (SELECT 1 FROM oauth2_registered_client WHERE lower(client_id) = ?)";

    @Mock
    JdbcTemplate jdbcTemplate;

    private ReservedClientIds reserved;

    @BeforeEach
    void setUp() {
        OidcClientProperties properties = new OidcClientProperties();
        OidcClientProperties.ClientDefinition configured = new OidcClientProperties.ClientDefinition();
        // Configured but possibly not seeded (blank optional secret): still reserved.
        configured.setClientId("claude-club-mcp");
        properties.getClients().add(configured);
        reserved = new ReservedClientIds(jdbcTemplate, properties);
    }

    @Test
    void configuredClientIdIsReservedWithoutDatabaseLookup() {
        assertThat(reserved.isReserved("claude-club-mcp")).isTrue();
        assertThat(reserved.isReserved(" Claude-Club-MCP ")).isTrue();
        verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void storedClientIdIsReservedIgnoringCaseAndWhitespace() {
        when(jdbcTemplate.queryForObject(EXISTS_SQL, Boolean.class, "furchert-ch")).thenReturn(true);

        assertThat(reserved.isReserved(" Furchert-CH ")).isTrue();
    }

    @Test
    void ordinaryNameIsNotReserved() {
        when(jdbcTemplate.queryForObject(eq(EXISTS_SQL), eq(Boolean.class), anyString())).thenReturn(false);

        assertThat(reserved.isReserved("alice")).isFalse();
        verify(jdbcTemplate).queryForObject(EXISTS_SQL, Boolean.class, "alice");
    }

    @Test
    void nullOrBlankIsNotReserved() {
        assertThat(reserved.isReserved(null)).isFalse();
        assertThat(reserved.isReserved("  ")).isFalse();
        verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void lockUsesTheSharedTransactionScopedAdvisoryLock() {
        reserved.lockIdentityNamespace();

        verify(jdbcTemplate).execute("SELECT pg_advisory_xact_lock(" + ReservedClientIds.IDENTITY_NAMESPACE_LOCK + ")");
    }
}
