package ch.furchert.homelab.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        String currentPassword,
        @NotBlank @Size(min = 8, max = 72) String newPassword
) {}
