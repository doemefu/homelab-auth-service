package ch.furchert.homelab.auth.dto;

import ch.furchert.homelab.auth.service.PasswordPolicy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        String currentPassword,
        @NotBlank @Size(min = PasswordPolicy.MIN_CHARACTERS, max = 72) String newPassword
) {
}
