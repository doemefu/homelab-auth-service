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
        // Deletes authorizations in two cases:
        // 1. At least one expires_at column is set AND the maximum expiration time has passed.
        //    COALESCE replaces NULL with epoch so GREATEST works correctly on partially-populated rows.
        // 2. All expires_at columns are NULL (abandoned/in-progress flow) AND the authorization was
        //    created more than 24 hours ago — allowing time for user interaction before cleanup.
        jdbcTemplate.update("""
            DELETE FROM oauth2_authorization
            WHERE (
                (
                    refresh_token_expires_at          IS NOT NULL
                    OR access_token_expires_at        IS NOT NULL
                    OR authorization_code_expires_at  IS NOT NULL
                    OR oidc_id_token_expires_at       IS NOT NULL
                    OR user_code_expires_at           IS NOT NULL
                    OR device_code_expires_at         IS NOT NULL
                )
                AND GREATEST(
                    COALESCE(refresh_token_expires_at,           to_timestamp(0)),
                    COALESCE(access_token_expires_at,            to_timestamp(0)),
                    COALESCE(authorization_code_expires_at,      to_timestamp(0)),
                    COALESCE(oidc_id_token_expires_at,           to_timestamp(0)),
                    COALESCE(user_code_expires_at,               to_timestamp(0)),
                    COALESCE(device_code_expires_at,             to_timestamp(0))
                ) < NOW()
            )
            OR (
                refresh_token_expires_at          IS NULL
                AND access_token_expires_at       IS NULL
                AND authorization_code_expires_at IS NULL
                AND oidc_id_token_expires_at      IS NULL
                AND user_code_expires_at          IS NULL
                AND device_code_expires_at        IS NULL
                AND authorization_code_issued_at  < NOW() - INTERVAL '24 hours'
            )
            """);
    }
}
