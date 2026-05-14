package ch.furchert.homelab.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory cache for the client_kind column of oauth2_registered_client.
 * <p>
 * Used by the JWT token customizer to decide whether to emit a device_id claim
 * on client_credentials access tokens. The cache is per-JVM and assumes a single
 * auth-service replica. Manual psql edits to client_kind require a service
 * restart to be picked up (documented in OPERATIONS.md).
 * <p>
 * Default-deny: unknown ids or absent client_kind values are treated as "not a
 * device client" so the device_id claim is omitted.
 */
@Service
@RequiredArgsConstructor
public class ClientKindLookup {

    static final String DEVICE = "device";

    private final JdbcTemplate jdbcTemplate;
    private final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();

    /**
     * @param registeredClientId the PK from oauth2_registered_client.id
     * @return the client_kind value, or null if the row does not exist
     */
    public String lookup(String registeredClientId) {
        return cache.computeIfAbsent(registeredClientId, this::loadFromDb);
    }

    public boolean isDevice(String registeredClientId) {
        return DEVICE.equals(lookup(registeredClientId));
    }

    public void invalidate(String registeredClientId) {
        cache.remove(registeredClientId);
    }

    private String loadFromDb(String registeredClientId) {
        try {
            return jdbcTemplate.queryForObject(
                    "SELECT client_kind FROM oauth2_registered_client WHERE id = ?",
                    String.class,
                    registeredClientId);
        } catch (EmptyResultDataAccessException _) {
            return null;
        }
    }
}
