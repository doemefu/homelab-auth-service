package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import ch.furchert.homelab.auth.repository.LoginEventOutboxRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Hourly purge of login-event outbox rows older than {@code app.login-events.ttl} (72 h,
 * docs/060 §7.6/§10). Runs even while the feature is disabled so rows from an earlier enabled
 * period never outlive the TTL.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginEventPurgeJob {

    private final LoginEventOutboxRepository repository;
    private final LoginEventProperties properties;

    @Scheduled(cron = "${app.login-events.purge-cron:0 0 * * * *}")
    public void purge() {
        int deleted = repository.purgeOlderThan(properties.getTtl());
        if (deleted > 0) {
            log.info("Purged {} login-event outbox row(s) older than {}", deleted, properties.getTtl());
        }
    }
}
