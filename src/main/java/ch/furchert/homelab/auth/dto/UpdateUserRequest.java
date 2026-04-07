package ch.furchert.homelab.auth.dto;

import ch.furchert.homelab.auth.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @Size(min = 3, max = 50) String username,
        @Email @Size(max = 100) String email,
        Role role,
        @Pattern(regexp = "ACTIVE|INACTIVE") String status
) {}
