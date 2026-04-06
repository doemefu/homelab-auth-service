package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;

    @Scheduled(fixedRate = 3600000)
    public void purgeExpiredTokens() {
        refreshTokenRepository.deleteByExpiresAtBefore(Instant.now());
    }
}
