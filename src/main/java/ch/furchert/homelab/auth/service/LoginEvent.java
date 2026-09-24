package ch.furchert.homelab.auth.service;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable login attempt captured on the request thread and inserted off it.
 * Holds personal data: never log instances of this record.
 */
public record LoginEvent(
        UUID eventId,
        Instant occurredAt,
        String outcome,
        String clientIp,
        String ipSource,
        String usernameHmac,
        String subject,
        String userAgent) {

    public static final String SUCCESS = "success";
    public static final String FAILURE = "failure";
    public static final String LOCKED = "locked";

    @Override
    public String toString() {
        // Keep IPs, user agents and usernames out of any accidental string conversion.
        return "LoginEvent[eventId=" + eventId + ", outcome=" + outcome + "]";
    }
}
