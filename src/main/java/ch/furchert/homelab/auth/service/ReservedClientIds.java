package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Locale;

/**
 * Registered client ids are reserved and cannot be used as usernames (#143). A name is reserved when it
 * equals, ignoring case and surrounding whitespace, a client id configured in {@code app.oidc.clients}
 * (also when that client is not seeded yet) or a client id stored in {@code oauth2_registered_client}
 * (SSO and IoT device clients).
 */
@Service
@RequiredArgsConstructor
public class ReservedClientIds {

    /** Transaction-scoped advisory lock shared by user create/rename and device-client create. */
    static final long IDENTITY_NAMESPACE_LOCK = 143_001L;

    private final JdbcTemplate jdbcTemplate;
    private final OidcClientProperties properties;

    public boolean isReserved(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        String normalized = normalize(name);
        boolean configured = properties.getClients().stream()
                .map(OidcClientProperties.ClientDefinition::getClientId)
                .anyMatch(id -> id != null && normalize(id).equals(normalized));
        return configured || Boolean.TRUE.equals(jdbcTemplate.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM oauth2_registered_client WHERE lower(client_id) = ?)",
                Boolean.class, normalized));
    }

    /**
     * True when an existing username equals {@code name}, both compared without surrounding whitespace and
     * ignoring case (used before a new client id is created).
     */
    public boolean isUsernameTaken(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        return Boolean.TRUE.equals(jdbcTemplate.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM users WHERE lower(regexp_replace(username, '^\\s+|\\s+$', '', 'g')) = ?)",
                Boolean.class, normalize(name)));
    }

    /**
     * Serialises user creates/renames against device-client creates until the surrounding transaction
     * ends, so both sides see each other's committed names. Call inside a transaction, before the checks.
     */
    public void lockIdentityNamespace() {
        jdbcTemplate.execute("SELECT pg_advisory_xact_lock(" + IDENTITY_NAMESPACE_LOCK + ")");
    }

    static String normalize(String name) {
        return name.strip().toLowerCase(Locale.ROOT);
    }
}
