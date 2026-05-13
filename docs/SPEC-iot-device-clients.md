# SPEC — IoT Device OAuth2 Clients

> Issue MQTT credentials for IoT devices via OAuth2 client-credentials. Devices receive a JWT that Mosquitto validates against `/oauth2/jwks`.

**Status:** draft
**Cross-references:**
- `../../device-service/SPEC-device-registration.md` — caller of the new admin API
- `../../infrastructure/docs/053-mqtt-device-authentication.md` — Mosquitto JWT plugin config

---

## Goal

Allow the homelab admin frontend (via device-service) to dynamically register, list, and revoke OAuth2 clients representing individual IoT devices. Each device authenticates to Mosquitto with a short-lived JWT obtained from `/oauth2/token` (grant `client_credentials`).

---

## Current state

- `AuthorizationServerConfig.registeredClientRepository()` uses **`InMemoryRegisteredClientRepository`** seeded from `app.oidc.clients` in `application.yaml`. Adding a client requires a config change + redeploy.
- Existing clients all use `AUTHORIZATION_CODE` + `REFRESH_TOKEN` grants for SSO (Grafana, HA, n8n, device-service, litellm).
- No `oauth2_registered_client` table exists. `OAuth2AuthorizationService` already uses JDBC (V3 migration covers `oauth2_authorization` + `oauth2_authorization_consent`).
- No support for `client_credentials` grant anywhere.

---

## Required changes

### 1. Flyway V5 — `oauth2_registered_client` table

New migration `V5__oauth2_registered_client.sql`. Use the standard Spring Authorization Server DDL (see `org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository` Javadoc — copy verbatim, adjust types to `timestamp with time zone` to match V2/V3 convention).

Adds one column **not** in the standard DDL:

```sql
ALTER TABLE oauth2_registered_client
    ADD COLUMN client_kind VARCHAR(20) NOT NULL DEFAULT 'sso';
-- Values: 'sso' (Grafana/HA/n8n/etc.) | 'device' (IoT)
CREATE INDEX idx_oauth2_registered_client_kind ON oauth2_registered_client(client_kind);
```

`client_kind` is used by the new admin API to filter `GET /api/v1/clients` to device clients only (so SSO clients don't show up in the device frontend).

### 2. Replace `InMemoryRegisteredClientRepository` with `JdbcRegisteredClientRepository`

In `AuthorizationServerConfig.java:98`:

- Return `new JdbcRegisteredClientRepository(jdbcOperations)`.
- Drop the in-memory list build.

### 3. Seed static SSO clients from config on startup

New `@Component` `StaticClientSeeder implements ApplicationRunner`:

- Iterate `OidcClientProperties.getClients()`.
- For each: `repo.findByClientId(...)`. If absent → `repo.save(buildRegisteredClient(def))`. If present → no-op (config is the source of truth for *bootstrap*, but updates after first save must go through the admin API or `psql`; document this explicitly).
- All seeded clients get `client_kind = 'sso'`. Persisting this requires a custom column write — easiest path: keep `client_kind` updates out of `JdbcRegisteredClientRepository` and write it via a small `JdbcTemplate` call right after `save()` (`UPDATE oauth2_registered_client SET client_kind = 'sso' WHERE id = ?`).
- Run order: after Flyway, before any HTTP traffic. `ApplicationRunner` runs at the right time.

### 4. Admin API — device client lifecycle

New controller `DeviceClientController` under `/api/v1/clients`. Secured: `hasRole('ADMIN')` **OR** authenticated client `device-service` (so service-to-service calls from device-service work without a user session).

| Method | Path | Body / Params | Response |
|--------|------|---------------|----------|
| `POST` | `/api/v1/clients` | `{ "clientId": "terra1", "description": "Greenhouse terrarium 1" }` | `201 { "clientId": "terra1", "clientSecret": "<plaintext, one-time>", "scopes": ["mqtt:pub", "mqtt:sub"] }` |
| `GET` | `/api/v1/clients` | — | `200 [{ "clientId": "terra1", "createdAt": "...", "description": "..." }]` (filters `client_kind='device'`) |
| `GET` | `/api/v1/clients/{clientId}` | — | `200` single client, or `404` |
| `DELETE` | `/api/v1/clients/{clientId}` | — | `204` — deletes from `oauth2_registered_client` **and** deletes outstanding rows from `oauth2_authorization` for that client (revokes tokens) |

Device client build defaults:

- Random `clientId` rejected — admin chooses (matches MQTT username, e.g. `terra1`).
- `clientSecret` generated server-side: 32 random bytes → Base64URL. Stored with `{bcrypt}` prefix. Returned **once** in the create response.
- Grants: `client_credentials` only.
- Scopes: `mqtt:pub`, `mqtt:sub`.
- `clientSettings`: `requireProofKey(false)`, `requireAuthorizationConsent(false)`.
- `tokenSettings`: `accessTokenTimeToLive(Duration.ofHours(1))`, no refresh tokens.
- `client_kind = 'device'`.

DTOs:

```java
public record CreateDeviceClientRequest(
    @NotBlank @Pattern(regexp="[a-z0-9-]{3,32}") String clientId,
    @Size(max=200) String description
) {}

public record DeviceClientResponse(
    String clientId, String description,
    Instant createdAt, List<String> scopes
) {}

public record DeviceClientCreatedResponse(
    String clientId, String clientSecret,
    List<String> scopes, Instant createdAt
) {}
```

Use a `DeviceClientService` for the logic so the controller stays thin and the same service can be unit-tested without MockMvc.

### 5. Token customizer — `device_id` claim

Extend `tokenCustomizer()` in `AuthorizationServerConfig`:

- For `client_credentials` access tokens, add claim `"device_id"` = `context.getRegisteredClient().getClientId()`.
- Mosquitto's JWT plugin will be configured to use this claim as the MQTT username for ACL evaluation.
- Keep the existing `role` claim logic untouched — it only fires when a principal authority is present (user-based grants).

### 6. Allow `client_credentials` on the token endpoint

`OAuth2AuthorizationServerConfiguration.applyDefaultSecurity` already enables `client_credentials` if the registered client requests it. **No filter chain changes expected** — verify in an integration test (Step 8).

### 7. Configuration

`application.yaml` additions:

```yaml
app:
  oidc:
    device-clients:
      access-token-ttl-seconds: 3600
      allowed-scopes: [mqtt:pub, mqtt:sub]
```

No env vars added — device secrets are generated, not configured.

### 8. Tests

- `DeviceClientControllerTest` (MockMvc, admin & service-to-service auth, validation, 404, idempotent delete).
- `DeviceClientServiceTest` (secret generation + bcrypt encoding, scope defaults, `client_kind='device'`).
- `StaticClientSeederTest` (seeds on empty DB, no-op on second run).
- Extend `OidcFlowIntegrationTest` with a `client_credentials` flow: register device → request token → assert JWT carries `device_id` claim + `mqtt:pub`/`mqtt:sub` scopes → assert signature validates via `/oauth2/jwks`.
- `FlywayMigrationTest` continues to pass on a fresh DB after adding V5.

---

## Out of scope

- Public RFC 7591 dynamic client registration endpoint — admin API is internal only.
- Refresh tokens for device clients — devices re-authenticate on token expiry, simpler than rotation.
- Per-topic scope granularity (`mqtt:pub:terra1/#`) — handled by Mosquitto ACL using `device_id`, not by scopes.
- Frontend UI — lives elsewhere (calls device-service, not auth-service directly).

---

## Risks

| Risk | Mitigation |
|------|------------|
| Seeder overwrites manual `psql` edits to SSO clients | Seeder uses `findByClientId` and skips if present. Document that post-bootstrap edits to SSO clients must use `psql` *or* the admin API, not `application.yaml`. |
| `client_kind` column drifts from grant type | Add an integration test that asserts every `client_credentials`-only client has `client_kind='device'`. |
| Plaintext secret in HTTP response logs | Add `@JsonIgnore`-style precaution in the controller logging filter; ensure Sentry breadcrumbs don't include response bodies for `/api/v1/clients`. |
| Long-lived bcrypt cost on Pi | bcrypt strength 10 is fine; profile if device fleet > 50. |

---

## Acceptance

- `curl -u device-service:<secret> -d 'grant_type=client_credentials' .../oauth2/token` for a registered device client returns a JWT containing `device_id` and `scope: "mqtt:pub mqtt:sub"`.
- `POST /api/v1/clients` followed by `DELETE` removes the client and invalidates outstanding tokens (Mosquitto rejects the JWT after delete + key cache invalidation interval).
- `GET /api/v1/clients` returns only `client_kind='device'` rows.
- Existing SSO flows (Grafana login, device-service Swagger SSO) are unchanged.
