package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.OidcClientProperties;
import ch.furchert.homelab.auth.dto.DeviceClientCreatedResponse;
import ch.furchert.homelab.auth.dto.DeviceClientResponse;
import ch.furchert.homelab.auth.exception.ResourceConflictException;
import ch.furchert.homelab.auth.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Lifecycle of IoT device OAuth2 clients (client_kind = 'device'). Methods are
 * transactional so the side-write to the client_kind column happens atomically
 * with RegisteredClientRepository.save().
 * <p>
 * Security note: create() returns the plaintext client secret exactly once.
 * Callers must surface it to the operator and never log it.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DeviceClientService {

    static final String CLIENT_KIND_DEVICE = "device";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String BCRYPT_PREFIX = "{bcrypt}";

    private final RegisteredClientRepository registeredClientRepository;
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;
    private final ClientKindLookup clientKindLookup;
    private final OidcClientProperties properties;

    @Transactional
    public DeviceClientCreatedResponse create(String clientId, String description) {
        if (registeredClientRepository.findByClientId(clientId) != null) {
            throw new ResourceConflictException("Client '" + clientId + "' already exists");
        }

        String plaintextSecret = generateSecret();
        String hashedSecret = passwordEncoder.encode(plaintextSecret);
        if (!hashedSecret.startsWith(BCRYPT_PREFIX)) {
            // DelegatingPasswordEncoder must emit a {bcrypt} prefix for the BCrypt
            // delegate to match on /oauth2/token authentication. Fail-fast to avoid
            // silently breaking the device client (memory: feedback_oidc_secret_prefix).
            throw new IllegalStateException(
                    "PasswordEncoder did not emit a {bcrypt} prefix; refusing to persist device client");
        }

        List<String> scopes = properties.getDeviceClients().getAllowedScopes();
        Duration ttl = Duration.ofSeconds(properties.getDeviceClients().getAccessTokenTtlSeconds());

        String id = UUID.randomUUID().toString();
        Instant now = Instant.now();
        RegisteredClient client = RegisteredClient.withId(id)
                .clientId(clientId)
                .clientIdIssuedAt(now)
                .clientName(description == null ? clientId : description)
                .clientSecret(hashedSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(s -> s.addAll(scopes))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(false)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(ttl)
                        .build())
                .build();

        registeredClientRepository.save(client);
        jdbcTemplate.update(
                "UPDATE oauth2_registered_client SET client_kind = ? WHERE id = ?",
                CLIENT_KIND_DEVICE, id);
        clientKindLookup.invalidate(id);

        log.info("Created device client '{}'", clientId);
        return new DeviceClientCreatedResponse(clientId, plaintextSecret, scopes, now);
    }

    public List<DeviceClientResponse> list() {
        return jdbcTemplate.query(
                "SELECT client_id, client_name, client_id_issued_at, scopes "
                        + "FROM oauth2_registered_client WHERE client_kind = ? "
                        + "ORDER BY client_id_issued_at DESC",
                (rs, rowNum) -> new DeviceClientResponse(
                        rs.getString("client_id"),
                        rs.getString("client_name"),
                        rs.getTimestamp("client_id_issued_at").toInstant(),
                        splitScopes(rs.getString("scopes"))),
                CLIENT_KIND_DEVICE);
    }

    public DeviceClientResponse get(String clientId) {
        try {
            return jdbcTemplate.queryForObject(
                    "SELECT client_id, client_name, client_id_issued_at, scopes "
                            + "FROM oauth2_registered_client "
                            + "WHERE client_kind = ? AND client_id = ?",
                    (rs, rowNum) -> new DeviceClientResponse(
                            rs.getString("client_id"),
                            rs.getString("client_name"),
                            rs.getTimestamp("client_id_issued_at").toInstant(),
                            splitScopes(rs.getString("scopes"))),
                    CLIENT_KIND_DEVICE, clientId);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException("Device client '" + clientId + "' not found");
        }
    }

    /**
     * Idempotent: returns silently if the device client does not exist OR is an
     * SSO client. The client_kind='device' guard on the initial SELECT prevents
     * a DELETE /api/v1/clients/grafana from wiping any oauth2_authorization rows
     * for the grafana SSO client.
     */
    @Transactional
    public void delete(String clientId) {
        String id;
        try {
            id = jdbcTemplate.queryForObject(
                    "SELECT id FROM oauth2_registered_client "
                            + "WHERE client_id = ? AND client_kind = ?",
                    String.class, clientId, CLIENT_KIND_DEVICE);
        } catch (EmptyResultDataAccessException e) {
            return;
        }
        if (id == null) {
            return;
        }

        jdbcTemplate.update(
                "DELETE FROM oauth2_authorization WHERE registered_client_id = ?", id);
        jdbcTemplate.update(
                "DELETE FROM oauth2_authorization_consent WHERE registered_client_id = ?", id);
        jdbcTemplate.update(
                "DELETE FROM oauth2_registered_client WHERE id = ?", id);
        clientKindLookup.invalidate(id);
        log.info("Deleted device client '{}'", clientId);
    }

    private static String generateSecret() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static List<String> splitScopes(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
