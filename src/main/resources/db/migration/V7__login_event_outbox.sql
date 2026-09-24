-- NM-4 (#94, docs/060 §7.6): transient outbox of form-login attempts, pulled by
-- data-service via GET /api/v1/login-events. Rows are purged after 72 h
-- (LoginEventPurgeJob). Personal data: client IPs, user agents and, for
-- successful logins only, the plaintext username (subject). Failed attempts carry
-- only a keyed HMAC of the submitted username.
CREATE TABLE login_event_outbox (
    id            BIGSERIAL    PRIMARY KEY,
    event_id      UUID         NOT NULL UNIQUE,
    occurred_at   TIMESTAMPTZ  NOT NULL,
    outcome       VARCHAR(16)  NOT NULL,
    client_ip     INET,
    ip_source     VARCHAR(32)  NOT NULL,
    username_hmac CHAR(64)     NOT NULL,
    subject       VARCHAR(255),
    user_agent    VARCHAR(512),
    recorded_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_login_event_outbox_outcome
        CHECK (outcome IN ('success', 'failure', 'locked')),
    CONSTRAINT chk_login_event_outbox_ip_source
        CHECK (ip_source IN ('cf-connecting-ip', 'remote-addr')),
    CONSTRAINT chk_login_event_outbox_subject_success_only
        CHECK (subject IS NULL OR outcome = 'success')
);

-- The primary key already serves the id-cursor scan; this index serves the hourly purge.
CREATE INDEX idx_login_event_outbox_recorded_at ON login_event_outbox (recorded_at);
