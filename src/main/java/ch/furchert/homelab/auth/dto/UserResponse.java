package ch.furchert.homelab.auth.dto;

import ch.furchert.homelab.auth.entity.User;

import java.time.Instant;

public record UserResponse(
        Long id,
        String username,
        String email,
        String role,
        String status,
        Instant createdAt,
        Instant updatedAt
) {
    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                user.getStatus(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}
