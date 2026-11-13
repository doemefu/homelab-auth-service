-- Remove the unused grafana and homeassistant SSO clients (#154): neither application is configured for OIDC login
-- against this IdP. Same pattern as V9: StaticClientSeeder never deletes rows, so removing the YAML entries alone
-- would leave the rows in place. Child rows reference the client's id (not its client_id), so they are selected
-- through the parent; children first, the client rows last. Only SSO rows are touched; on a database without these
-- rows every statement matches 0 rows, so re-running is a no-op.

DELETE FROM oauth2_authorization_consent
WHERE registered_client_id IN
      (SELECT id FROM oauth2_registered_client WHERE client_id IN ('grafana', 'homeassistant') AND client_kind = 'sso');

DELETE FROM oauth2_authorization
WHERE registered_client_id IN
      (SELECT id FROM oauth2_registered_client WHERE client_id IN ('grafana', 'homeassistant') AND client_kind = 'sso');

DELETE FROM oauth2_registered_client
WHERE client_id IN ('grafana', 'homeassistant') AND client_kind = 'sso';
