-- #107 (docs/080 §4.1): consent decisions are persisted by Spring Authorization Server's JDBC
-- consent service and must be traceable. SAS inserts and selects with explicit column lists, so
-- these defaults fill both columns and loads ignore them; its UPDATE sets only authorities, so
-- AuditingAuthorizationConsentService refreshes updated_at on every save.
-- Additive and metadata-only (constant default): the previous image keeps working on this schema.
ALTER TABLE oauth2_authorization_consent
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
