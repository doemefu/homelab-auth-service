SET timezone = 'UTC';

-- Convert all timestamp columns to timestamptz for correct timezone handling
ALTER TABLE users ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE users ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

ALTER TABLE refresh_tokens ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE refresh_tokens ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

-- Widen password_hash to accommodate future hashing algorithms
ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255);

-- Resize refresh token column — now stores SHA-256 hex hashes (64 chars) instead of raw tokens
TRUNCATE refresh_tokens;
ALTER TABLE refresh_tokens ALTER COLUMN token TYPE VARCHAR(64);
