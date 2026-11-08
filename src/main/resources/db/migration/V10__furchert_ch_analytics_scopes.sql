-- WA-0 (homelab#348, homelab-auth-service#142, docs/100-web-analytics.md §11):
-- give the existing furchert-ch client the analytics:write and analytics:read scopes so
-- furchert-ch can fetch one client_credentials service token per scope for data-service
-- (client_credentials itself is already granted by V6). V9 is taken by the n8n removal (#140).
--
-- StaticClientSeeder skips client_ids that already exist, so the YAML change only
-- covers fresh databases; this migration is the path for existing ones.
-- scopes holds a SAS comma-separated list (no spaces, unordered). Each UPDATE appends
-- its value only when absent, so re-running is a no-op; on a fresh database (no
-- furchert-ch row yet) both statements match 0 rows.

UPDATE oauth2_registered_client
SET scopes = array_to_string(
        array_append(string_to_array(scopes, ','), 'analytics:write'), ',')
WHERE client_id = 'furchert-ch'
  AND NOT ('analytics:write' = ANY (string_to_array(scopes, ',')));

UPDATE oauth2_registered_client
SET scopes = array_to_string(
        array_append(string_to_array(scopes, ','), 'analytics:read'), ',')
WHERE client_id = 'furchert-ch'
  AND NOT ('analytics:read' = ANY (string_to_array(scopes, ',')));
