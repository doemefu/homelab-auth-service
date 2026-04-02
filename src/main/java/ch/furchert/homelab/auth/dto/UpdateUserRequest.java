package ch.furchert.homelab.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @Size(min = 3, max = 50) String username,
        @Email @Size(max = 100) String email,
        @Pattern(regexp = "USER|ADMIN") String role,
        @Pattern(regexp = "ACTIVE|INACTIVE") String status
) {}
