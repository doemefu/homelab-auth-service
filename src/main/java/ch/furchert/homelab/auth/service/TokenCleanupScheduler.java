package ch.furchert.homelab.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final JdbcTemplate jdbcTemplate;

    @Scheduled(fixedRate = 3_600_000)
    @Transactional
    public void purgeExpiredAuthorizations() {
        jdbcTemplate.update("""
            DELETE FROM oauth2_authorization
            WHERE GREATEST(
                refresh_token_expires_at,
                access_token_expires_at,
                authorization_code_expires_at,
                oidc_id_token_expires_at,
                user_code_expires_at,
                device_code_expires_at
            ) < NOW()
            OR (
                GREATEST(
                    refresh_token_expires_at,
                    access_token_expires_at,
                    authorization_code_expires_at,
                    oidc_id_token_expires_at,
                    user_code_expires_at,
                    device_code_expires_at
                ) IS NULL
                AND authorization_code_issued_at < NOW() - INTERVAL '24 hours'
            )
            """);
    }
}
