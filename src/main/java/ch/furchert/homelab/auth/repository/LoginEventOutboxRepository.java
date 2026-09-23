package ch.furchert.homelab.auth.repository;

import ch.furchert.homelab.auth.dto.LoginEventResponse;
import ch.furchert.homelab.auth.service.LoginEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Duration;
import java.util.List;

/**
 * JDBC access to {@code login_event_outbox} (V7). JdbcTemplate rather than JPA because the
 * {@code inet} column needs explicit casts, like the other infrastructure tables handled with
 * JdbcTemplate ({@code TokenCleanupScheduler}, {@code ClientKindLookup}).
 */
@Repository
@RequiredArgsConstructor
public class LoginEventOutboxRepository {

    private final JdbcTemplate jdbcTemplate;

    public void insert(LoginEvent e) {
        jdbcTemplate.update("""
                INSERT INTO login_event_outbox
                    (event_id, occurred_at, outcome, client_ip, ip_source, username_hmac, subject, user_agent)
                VALUES (?, ?, ?, CAST(? AS inet), ?, ?, ?, ?)
                """,
                e.eventId(), Timestamp.from(e.occurredAt()), e.outcome(), e.clientIp(), e.ipSource(),
                e.usernameHmac(), e.subject(), e.userAgent());
    }

    /**
     * Rows with {@code id > after} that are at least {@code settle} old, ordered by id.
     * The settle window keeps ids whose inserting transaction commits late from being skipped.
     */
    public List<LoginEventResponse> findAfter(long after, int limit, Duration settle) {
        return jdbcTemplate.query("""
                SELECT id, event_id, occurred_at, outcome, host(client_ip) AS client_ip, ip_source,
                       username_hmac, subject, user_agent
                FROM login_event_outbox
                WHERE id > ?
                  AND recorded_at <= now() - make_interval(secs => ?)
                ORDER BY id
                LIMIT ?
                """,
                (rs, rowNum) -> new LoginEventResponse(
                        rs.getLong("id"),
                        rs.getObject("event_id", java.util.UUID.class),
                        rs.getTimestamp("occurred_at").toInstant(),
                        rs.getString("outcome"),
                        rs.getString("client_ip"),
                        rs.getString("ip_source"),
                        rs.getString("username_hmac"),
                        rs.getString("subject"),
                        rs.getString("user_agent")),
                after, (double) settle.toMillis() / 1000d, limit);
    }

    /** @return number of rows deleted */
    public int purgeOlderThan(Duration ttl) {
        return jdbcTemplate.update(
                "DELETE FROM login_event_outbox WHERE recorded_at < now() - make_interval(secs => ?)",
                (double) ttl.toSeconds());
    }
}
