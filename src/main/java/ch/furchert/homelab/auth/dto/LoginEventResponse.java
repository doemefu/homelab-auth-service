package ch.furchert.homelab.auth.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * One outbox row as served to data-service (docs/060 §7.6). Absent values are {@code null},
 * never omitted. {@code subject} is set only for {@code outcome=success}.
 */
public record LoginEventResponse(
        long id,
        UUID eventId,
        Instant occurredAt,
        String outcome,
        String clientIp,
        String ipSource,
        String usernameHmac,
        String subject,
        String userAgent) {
}
