package ch.furchert.homelab.auth.dto;

import java.util.List;

/**
 * Page of the login-event outbox. {@code nextAfter} is the id to pass as {@code after} next time
 * (the request's {@code after} when the page is empty); {@code hasMore} tells the caller to fetch
 * again immediately.
 */
public record LoginEventPage(List<LoginEventResponse> events, long nextAfter, boolean hasMore) {
}
