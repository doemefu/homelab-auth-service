-- Remove the unused n8n SSO client: n8n community edition cannot use OIDC, n8n uses local login.
-- StaticClientSeeder never deletes rows, so removing the YAML entry alone would leave the row (and its
-- plaintext {noop} secret) in place. Child rows reference the client's id (not its client_id), so they are
-- selected through the parent; children first, the client row last. Only an SSO row is touched; on a
-- database without that row every statement matches 0 rows, so re-running is a no-op.

DELETE FROM oauth2_authorization_consent
WHERE registered_client_id IN
      (SELECT id FROM oauth2_registered_client WHERE client_id = 'n8n' AND client_kind = 'sso');

DELETE FROM oauth2_authorization
WHERE registered_client_id IN
      (SELECT id FROM oauth2_registered_client WHERE client_id = 'n8n' AND client_kind = 'sso');

DELETE FROM oauth2_registered_client
WHERE client_id = 'n8n' AND client_kind = 'sso';
