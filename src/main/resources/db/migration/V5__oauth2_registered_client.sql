-- Spring Authorization Server registered-client schema (SAS 7.0.5 stock DDL),
-- with timestamps adjusted to timestamp with time zone to match V2/V3 conventions.
-- See org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
SET timezone = 'UTC';

CREATE TABLE IF NOT EXISTS oauth2_registered_client
(
    id                            varchar(100)             NOT NULL,
    client_id                     varchar(100)             NOT NULL,
    client_id_issued_at           timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_secret                 varchar(200)             DEFAULT NULL,
    client_secret_expires_at      timestamp with time zone DEFAULT NULL,
    client_name                   varchar(200)             NOT NULL,
    client_authentication_methods varchar(1000)            NOT NULL,
    authorization_grant_types     varchar(1000)            NOT NULL,
    redirect_uris                 varchar(1000)            DEFAULT NULL,
    post_logout_redirect_uris     varchar(1000)            DEFAULT NULL,
    scopes                        varchar(1000)            NOT NULL,
    client_settings               varchar(2000)            NOT NULL,
    token_settings                varchar(2000)            NOT NULL,
    PRIMARY KEY (id)
);

-- Extension column: classifies a registered client. 'sso' for human SSO clients
-- (Grafana/HA/n8n/device-service/litellm), 'device' for IoT clients managed
-- through the admin API. Used by the token customizer to emit device_id only
-- for IoT clients, and by the admin API to filter listings.
ALTER TABLE oauth2_registered_client
    ADD COLUMN client_kind VARCHAR(20) NOT NULL DEFAULT 'sso';

CREATE UNIQUE INDEX idx_oauth2_registered_client_client_id
    ON oauth2_registered_client (client_id);

CREATE INDEX idx_oauth2_registered_client_kind
    ON oauth2_registered_client (client_kind);
