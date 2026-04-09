-- Drop the legacy refresh_tokens table now that all token storage has moved to
-- oauth2_authorization (created in V3 by Spring Authorization Server).
DROP TABLE IF EXISTS refresh_tokens;
