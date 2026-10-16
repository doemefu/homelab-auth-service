package ch.furchert.homelab.auth.dto;

import java.util.List;

/**
 * One page of GET /api/v1/users, ordered by id ascending. {@code page} is zero-based;
 * {@code totalElements} counts all users, so callers can derive the page count.
 */
public record UserPage(List<UserResponse> users, int page, int size, long totalElements) {
}
