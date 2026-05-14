package ch.furchert.homelab.auth.dto;

import java.time.Instant;
import java.util.List;

/**
 * Returned from POST /api/v1/clients. Contains the plaintext client secret —
 * shown once and never persisted in clear. Never log this response body.
 */
public record DeviceClientCreatedResponse(
        String clientId,
        String clientSecret,
        List<String> scopes,
        Instant createdAt
) {
}
