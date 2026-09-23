package ch.furchert.homelab.auth.controller;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import ch.furchert.homelab.auth.dto.LoginEventPage;
import ch.furchert.homelab.auth.dto.LoginEventResponse;
import ch.furchert.homelab.auth.exception.LoginEventsDisabledException;
import ch.furchert.homelab.auth.repository.LoginEventOutboxRepository;
import ch.furchert.homelab.auth.service.LoginEventFeature;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Pull endpoint for the login-event outbox (docs/060 §7.6), consumed by data-service with a
 * client-credentials token carrying {@code login-events:read}. The chain-wide
 * {@code authenticated()} rule would also admit user tokens (including ADMIN), so the scope is
 * enforced here with method security.
 */
@RestController
@RequestMapping("/api/v1/login-events")
@RequiredArgsConstructor
public class LoginEventController {

    private final LoginEventOutboxRepository repository;
    private final LoginEventFeature feature;
    private final LoginEventProperties properties;

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_login-events:read')")
    public LoginEventPage list(@RequestParam(defaultValue = "0") long after,
                               @RequestParam(required = false) Integer limit) {
        if (!feature.isEnabled()) {
            throw new LoginEventsDisabledException();
        }
        int max = properties.getMaxLimit();
        int size = limit == null ? properties.getDefaultLimit() : limit;
        if (after < 0) {
            throw new IllegalArgumentException("after must be >= 0");
        }
        if (size < 1 || size > max) {
            throw new IllegalArgumentException("limit must be between 1 and " + max);
        }

        List<LoginEventResponse> rows = repository.findAfter(after, size + 1, properties.getSettle());
        boolean hasMore = rows.size() > size;
        List<LoginEventResponse> page = hasMore ? rows.subList(0, size) : rows;
        long nextAfter = page.isEmpty() ? after : page.getLast().id();
        return new LoginEventPage(List.copyOf(page), nextAfter, hasMore);
    }
}
