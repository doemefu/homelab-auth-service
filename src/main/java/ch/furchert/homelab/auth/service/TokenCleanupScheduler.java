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
        // COALESCE replaces NULL with epoch so GREATEST never returns NULL for a partially-populated row.
        // The all-NULL branch catches abandoned auth flows where no token was ever issued.
        jdbcTemplate.update("""
            DELETE FROM oauth2_authorization
            WHERE GREATEST(
                COALESCE(refresh_token_expires_at,           to_timestamp(0)),
                COALESCE(access_token_expires_at,            to_timestamp(0)),
                COALESCE(authorization_code_expires_at,      to_timestamp(0)),
                COALESCE(oidc_id_token_expires_at,           to_timestamp(0)),
                COALESCE(user_code_expires_at,               to_timestamp(0)),
                COALESCE(device_code_expires_at,             to_timestamp(0))
            ) < NOW()
            OR (
                refresh_token_expires_at          IS NULL
                AND access_token_expires_at       IS NULL
                AND authorization_code_expires_at IS NULL
                AND oidc_id_token_expires_at      IS NULL
                AND user_code_expires_at          IS NULL
                AND device_code_expires_at        IS NULL
                AND authorization_code_issued_at < NOW() - INTERVAL '24 hours'
            )
            """);
    }
}
