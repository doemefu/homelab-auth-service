-- NM-0 (homelab#114, homelab-auth-service#93, docs/060-network-monitoring.md §7.5):
-- give the existing furchert-ch SSO client the client_credentials grant and the
-- netmon:read scope so furchert-ch can fetch a service token for data-service.
--
-- StaticClientSeeder skips client_ids that already exist, so the YAML change only
-- covers fresh databases; this migration is the path for existing ones.
-- Both columns hold SAS comma-separated lists (no spaces, unordered). Each UPDATE
-- appends its value only when absent, so re-running is a no-op; on a fresh
-- database (no furchert-ch row yet) both statements match 0 rows.

UPDATE oauth2_registered_client
SET authorization_grant_types = array_to_string(
        array_append(string_to_array(authorization_grant_types, ','), 'client_credentials'), ',')
WHERE client_id = 'furchert-ch'
  AND NOT ('client_credentials' = ANY (string_to_array(authorization_grant_types, ',')));

UPDATE oauth2_registered_client
SET scopes = array_to_string(
        array_append(string_to_array(scopes, ','), 'netmon:read'), ',')
WHERE client_id = 'furchert-ch'
  AND NOT ('netmon:read' = ANY (string_to_array(scopes, ',')));
