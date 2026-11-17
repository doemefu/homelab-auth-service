package ch.furchert.homelab.auth.dto;

import ch.furchert.homelab.auth.service.PasswordPolicy;
import ch.furchert.homelab.auth.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
        @NotBlank @Size(min = 3, max = 50) String username,
        @NotBlank @Email @Size(max = 100) String email,
        @NotBlank @Size(min = PasswordPolicy.MIN_CHARACTERS, max = 72) String password,
        Role role
) {
}
