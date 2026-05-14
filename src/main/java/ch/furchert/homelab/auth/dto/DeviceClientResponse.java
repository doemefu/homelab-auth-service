package ch.furchert.homelab.auth.dto;

import java.time.Instant;
import java.util.List;

public record DeviceClientResponse(
        String clientId,
        String description,
        Instant createdAt,
        List<String> scopes
) {
}
