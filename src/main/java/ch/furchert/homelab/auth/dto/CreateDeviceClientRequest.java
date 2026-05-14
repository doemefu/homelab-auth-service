package ch.furchert.homelab.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for POST /api/v1/clients. The clientId pattern matches MQTT username rules
 * (lowercase alphanumerics + dash, 3..32 chars).
 */
public record CreateDeviceClientRequest(
        @NotBlank
        @Pattern(regexp = "[a-z0-9-]{3,32}", message = "clientId must match [a-z0-9-]{3,32}")
        String clientId,
        @Size(max = 200)
        String description
) {
}
