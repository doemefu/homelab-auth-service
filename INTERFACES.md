# homelab-auth-service — Interfaces

This document describes how external services, applications, and clients interact with `homelab-auth-service`.

---

## Interface Types

The auth-service exposes **three types of interfaces**:

1. **OIDC Protocol Endpoints** — For OIDC-compatible clients (Grafana, Home Assistant, n8n, LiteLLM)
2. **REST API** — For programmatic user management (admin operations)
3. **JWKS Endpoint** — For service-to-service token validation

---

## 1. OIDC Client Integration

### Standard OIDC Configuration

All OIDC clients should use the following configuration:

| Parameter | Value |
|-----------|-------|
| **Discovery URL** | `https://auth.furchert.ch/.well-known/openid-configuration` |
| **Issuer** | `https://auth.furchert.ch` |
| **Authorization Endpoint** | `https://auth.furchert.ch/oauth2/authorize` |
| **Token Endpoint** | `https://auth.furchert.ch/oauth2/token` |
| **UserInfo Endpoint** | `https://auth.furchert.ch/userinfo` |
| **JWKS URI** | `https://auth.furchert.ch/oauth2/jwks` |
| **End Session Endpoint** | `https://auth.furchert.ch/connect/logout` |

### Supported Grant Types

| Grant Type | Supported | Notes |
|------------|-----------|-------|
| Authorization Code | ✅ Yes | With PKCE required |
| Refresh Token | ✅ Yes | Issued automatically |
| Client Credentials | ✅ Yes | IoT device clients (§8), `device-service` (`clients:admin`) and `furchert-ch` (`netmon:read`, §2) |
| Password | ❌ No | Not supported |

### Required Scopes

- `openid` (required)
- `profile` (recommended)
- `email` (recommended)

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."
}
```

### ID Token Claims

Standard OIDC claims plus custom claims:

```json
{
  "sub": "username",
  "name": "username",
  "email": "user@example.com",
  "role": "ADMIN",
  "iss": "https://auth.furchert.ch",
  "aud": "client-id",
  "iat": 1714234567,
  "exp": 1714235467
}
```

The `role` claim contains the user's role (`USER` or `ADMIN`).

### UserInfo Response

```json
{
  "sub": "username",
  "name": "username",
  "email": "user@example.com",
  "role": "ADMIN"
}
```

Note: The `role` claim in UserInfo is **not** prefixed with `ROLE_`.

### RP-Initiated Logout

```
GET /connect/logout?id_token_hint=<id_token>&post_logout_redirect_uri=<registered URI>
```

- `id_token_hint` is **required** and must resolve to a stored authorization:
  - Authorizations are purged by `TokenCleanupScheduler` roughly 7 days after login (the
    refresh-token TTL).
  - An ID token issued in a different IdP browser session (`sid` mismatch) is rejected.
- On success: the IdP session is ended and the browser is redirected to the registered
  `post_logout_redirect_uri`.
- On error: if `id_token_hint` is a token **signed by this server** (even if it is
  expired or its authorization row has already been purged), the IdP still ends its
  local session and redirects to `/login?logout` — never to the requested URI, since it
  cannot be validated against the registered client without a resolvable
  `id_token_hint`. Any other hint (missing, forged, garbage) gets the standard
  `400 invalid_token` error page instead, and the IdP session is left untouched — this
  keeps `/connect/logout?id_token_hint=<anything>` from being usable as a cross-site
  forced-logout link.
- RPs whose own session outlives ~7 days (e.g. furchert-ch's 30-day sliding Auth.js
  session) should expect the `/login?logout` landing in that case, not an error page.

---

## 2. Client-Specific Integration Guides

### Grafana

Grafana uses the Generic OAuth provider. Add to `grafana.ini`:

```ini
[auth.generic_oauth]
enabled = true
name = Homelab SSO
icon = signin
client_id = grafana
client_secret = ${GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET}
scopes = openid profile email
auth_url = https://auth.furchert.ch/oauth2/authorize
token_url = https://auth.furchert.ch/oauth2/token
api_url = https://auth.furchert.ch/userinfo
use_pkce = true
role_attribute_path = role == 'ADMIN' && 'Admin' || 'Viewer'
```

**Note:** Set `role_attribute_path` to map the `role` claim to Grafana roles. Adjust the expression based on your Grafana permission model.

### Home Assistant

In `configuration.yaml`:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 10.0.0.0/8

oidc:
  discovery_url: https://auth.furchert.ch/.well-known/openid-configuration
  client_id: homeassistant
  client_secret: !secret ha_oidc_client_secret
  scopes:
    - openid
    - profile
    - email
```

Add to `secrets.yaml`:
```yaml
ha_oidc_client_secret: <plaintext-secret>
```

### n8n

n8n OIDC configuration:

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://auth.furchert.ch",
    "clientId": "n8n",
    "clientSecret": "<plaintext-secret>",
    "redirectUri": "https://n8n.furchert.ch/rest/sso/oidc/callback",
    "scopes": ["openid", "profile", "email"],
    "usePkce": true
  }
}
```

### LiteLLM

Configure LiteLLM's OIDC integration:

```yaml
# In your LiteLLM config
sso:
  provider: oidc
  oidc:
    issuer: https://auth.furchert.ch
    client_id: litellm
    client_secret: <plaintext-secret>
    redirect_uri: https://ai.furchert.ch/sso/callback
    scopes: ["openid", "profile", "email"]
    use_pkce: true
```

### device-service (Spring Boot)

device-service uses Spring Security OAuth2 Client. In `application.yaml`:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          auth-service:
            client-id: device-service
            client-secret: ${DEVICE_SERVICE_CLIENT_SECRET}
            authorization-grant-type: authorization_code
            scope: openid,profile,email
            redirect-uri: "https://device.furchert.ch/login/oauth2/code/device-service"
        provider:
          auth-service:
            issuer-uri: https://auth.furchert.ch
```

For token validation (resource server config):

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.furchert.ch
          jwk-set-uri: http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks
```

### furchert-ch — service token for data-service (`netmon:read`)

The `furchert-ch` client has `authorization_code` + `refresh_token` (dashboard SSO)
**and** `client_credentials`, with the extra scope `netmon:read`. furchert-ch uses
it server-side to call the data-service network-monitoring API
(contract: `../docs/060-network-monitoring.md` §7.5). No new secret: the request
uses the existing furchert-ch client secret.

```bash
curl -s -u "furchert-ch:${OIDC_CLIENT_SECRET}" \
  -d 'grant_type=client_credentials&scope=netmon:read' \
  http://auth-service.apps.svc.cluster.local:8080/oauth2/token
```

Transport: this call is cluster-internal plain HTTP, the same path as every other
in-cluster call to auth-service (TLS terminates at the Cloudflare edge), so the
client secret crosses the cluster pod network as Basic auth. No NetworkPolicy
restricts who can reach auth-service today; the mitigation is the NetworkPolicy
follow-up in `../docs/060-network-monitoring.md` §10 (auth-service :8080 ingress
only from cloudflared, furchert-ch and data-service).

The access token carries `sub=furchert-ch`, `aud=furchert-ch` and
`scope=["netmon:read"]`, with no `role` and no `device_id` claim. Only explicitly
requested scopes are granted, and a client without `netmon:read` gets
`400 invalid_scope`. Existing databases receive the grant and scope through Flyway
`V6__furchert_ch_client_credentials.sql`; fresh databases get them from
`application.yaml` via the seeder.

### data-service — login-event pull (`login-events:read`)

auth-service keeps a transient outbox of form-login attempts that data-service pulls
(network monitoring NM-4; contract: `../docs/060-network-monitoring.md` §7.6, §9, §10).
auth-service makes no outbound call: data-service pulls, auth-service only exposes.

**Client.** `data-service`, grant `client_credentials` only, scope `login-events:read`,
no redirect URIs. It is seeded from `application.yaml` on the first boot where its
secret is set; while the secret is blank the seeder skips it.

```bash
curl -s -u "data-service:${AUTH_CLIENT_SECRET}" \
  -d 'grant_type=client_credentials&scope=login-events:read' \
  http://auth-service.apps.svc.cluster.local:8080/oauth2/token
```

**Endpoint.** `GET /api/v1/login-events?after=<id>&limit=<n>`

| Parameter | Default | Rule |
|---|---|---|
| `after` | `0` | id cursor, `>= 0`; returns rows with `id > after` |
| `limit` | `500` | `1..1000`, otherwise `400` |

- Requires `SCOPE_login-events:read` via method security. A user token, including one
  with `role=ADMIN`, gets `403`; no token gets `401`.
- Returns `503` while the feature is disabled (see Configuration below). The scope
  check runs first, so an unscoped caller still gets `403`.
- Rows younger than 10 s are not served yet, so ids whose transaction commits late
  are never skipped. Pass `nextAfter` back as `after`, and fetch again at once while
  `hasMore` is true.
- Responses carry Spring Security's default `Cache-Control: no-cache, no-store`.

```json
{ "events": [ {"id": 1234, "eventId": "0b6f…", "occurredAt": "2026-09-23T21:00:00.123Z",
               "outcome": "failure", "clientIp": "203.0.113.7", "ipSource": "cf-connecting-ip",
               "usernameHmac": "<64 hex>", "subject": null, "userAgent": "…"} ],
  "nextAfter": 1234, "hasMore": false }
```

| Field | Meaning |
|---|---|
| `outcome` | `success`; `locked` = the account is not `ACTIVE` (checked before the password); `failure` = anything else |
| `clientIp`, `ipSource` | `CF-Connecting-IP` when it holds a valid IP literal (`cf-connecting-ip`), else the request's remote address (`remote-addr`). Tomcat's RemoteIpValve can already derive the remote address from `X-Forwarded-For`, so both are header-derived and spoofable in-cluster. `clientIp` is `null` when neither is a valid IP. |
| `usernameHmac` | Lowercase hex `HMAC-SHA256(LOGIN_EVENT_HMAC_KEY, lowercase(trim(submitted username)))`. The key never leaves auth-service. |
| `subject` | Plaintext username, set **only** for `success` |
| `userAgent` | Truncated to 512 characters; `null` when absent |

Absent values are `null`, never omitted. Only form logins on `/login` are recorded;
bearer-token and OAuth2 client authentications are not.

**Capture and retention.** The Spring Security authentication event listener captures
the request data on the login thread and hands it to one bounded background writer.
When its queue is full the event is dropped with a rate-limited WARN, so a login never
fails or slows down because of telemetry. Rows are purged hourly once `recorded_at` is
older than 72 h. Privacy: log lines never contain IPs, usernames or user agents, but
`homelabdb` dumps and Longhorn snapshots capture up to 72 h of outbox rows.

**Configuration.**

| Env | Kubernetes Secret key (`homelab-auth-secrets`) | SOPS variable (owner) |
|---|---|---|
| `DATA_SERVICE_CLIENT_SECRET` | `data-service-client-secret`, value `{noop}<plaintext>` | `auth_service_data_service_client_secret` (data-service uses the plain value) |
| `LOGIN_EVENT_HMAC_KEY` | `login-event-hmac-key`, at least 32 characters, e.g. `openssl rand -hex 32` | `auth_service_login_event_hmac_key` |

Both env vars are **optional**, and `k8s/deployment.yaml` wires them with
`optional: true`. auth-service is Flux-auto-deployed on merge and is the sole IdP, so a
missing Secret key must never stop the pod. While either is missing or the key is too
short, the app starts normally, does not seed `data-service`, records nothing, answers
`503` on the endpoint, and logs one WARN naming the missing variable. Enabling it takes
the SOPS variables, a playbook 59 run that creates the Secret keys, and an auth-service
restart. Rotating the HMAC key breaks HMAC continuity with events already stored in
data-service. Other settings live under `app.login-events.*`: `ttl` 72h, `settle` 10s,
`queue-capacity` 1000, `default-limit` 500, `max-limit` 1000, and `purge-cron`, which
runs hourly.

---

## 3. Service-to-Service Token Validation

Downstream services validate JWT tokens by:

1. **Fetching the JWKS** from `https://auth.furchert.ch/oauth2/jwks` (or cluster-internal URL)
2. **Caching the public keys** by `kid` (key ID)
3. **Validating token signatures** locally

### JWKS Endpoint

```bash
# Public access
curl -s https://auth.furchert.ch/oauth2/jwks | jq

# Cluster-internal access
curl -s http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks | jq
```

Response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "auth-service-v1",
      "alg": "RS256",
      "n": "x0G4..."
    }
  ]
}
```

### Token Validation Configuration

For Spring Boot services using `spring-boot-starter-oauth2-resource-server`:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.furchert.ch
          jwk-set-uri: http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks
```

**Important:** For cluster-internal services, use the internal JWKS URI (`http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks`) to avoid external network calls. The public URL (`https://auth.furchert.ch/oauth2/jwks`) can also be used but adds latency.

### Custom Validation (Non-Spring)

For services not using Spring Security, implement JWT validation using the JWKS:

1. Cache the JWKS response
2. Extract the `n` (modulus) and `e` (exponent) values
3. Reconstruct the RSA public key
4. Verify the token signature
5. Validate claims:
   - `iss` = `https://auth.furchert.ch`
   - `aud` = your client ID
   - `exp` > current time

---

## 4. REST API Interface

### Base URL

- **Production:** `https://auth.furchert.ch/api/v1`
- **Cluster-internal:** `http://auth-service.apps.svc.cluster.local:8080/api/v1`

### Authentication

The REST API uses **Bearer token authentication** with JWT tokens obtained via OIDC flow.

- **Header:** `Authorization: Bearer <token>`
- **Token Type:** Access token from OIDC token endpoint

### Authorization Rules

| Endpoint | Required Role | Notes |
|----------|---------------|-------|
| `GET /users/{id}` | Any authenticated | User can access own profile |
| All other `/users` endpoints | `ADMIN` | Full CRUD access |
| All `/clients` endpoints | `ADMIN` **or** `clients:admin` scope | IoT device client lifecycle — see §8 |
| `GET /login-events` | `login-events:read` scope only (ADMIN gets 403) | Login-event outbox for data-service — see §2 "data-service" |

### API Summary

See [OVERVIEW.md](./OVERVIEW.md#accessible-urls--apis) for the complete API reference.

### OpenAPI Specification

```bash
# Download OpenAPI spec
curl -s https://auth.furchert.ch/api-docs > openapi.json

# Or cluster-internal
curl -s http://auth-service.apps.svc.cluster.local:8080/api-docs > openapi.json
```

---

## 5. Health & Monitoring Interfaces

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /actuator/health` | Liveness probe — returns `{"status":"UP"}` |
| `GET /actuator/info` | Service metadata — name, version, etc. |

Both endpoints are **unauthenticated** and accessible without tokens.

### Kubernetes Probes

The deployment uses:
- **Startup Probe:** `GET /actuator/health` (5s period, 60 failures — 300s budget)
- **Liveness Probe:** `GET /actuator/health` (10s period, 3 failures)
- **Readiness Probe:** `GET /actuator/health` (5s period, 3 failures)

---

## 6. Configure a New OIDC Client

To add a new OIDC client to auth-service:

> **Note — registered clients are JDBC-backed.** Clients are persisted in the
> `oauth2_registered_client` table (Flyway V5). The `app.oidc.clients` list in
> `application.yaml` is **bootstrap-only**: `StaticClientSeeder` seeds each
> entry on first boot and **skips any client that already exists**. After the
> first boot, editing or removing an existing client in `application.yaml` has
> no effect — change it via a Flyway migration (precedent: `V6`, furchert-ch),
> `psql` or, for IoT device clients, the admin API (§8). The steps below apply to the initial bootstrap of a new SSO client.

### Step 1: Generate Client Secret

Choose one encoding method:

**Option A: Plaintext (homelab convention)**
```bash
# The secret value stored in K8s will be: {noop}<your-secret>
CLIENT_SECRET_ENCODED="{noop}my-very-secure-secret"
```

**Option B: BCrypt hashed (more secure)**
```bash
# Generate BCrypt hash
HASH=$(htpasswd -bnBC 12 "" "my-very-secure-secret" | tr -d ':\n')
# The secret value stored in K8s will be: {bcrypt}$2a$12$...
CLIENT_SECRET_ENCODED="{bcrypt}${HASH}"
```

### Step 2: Create/Update K8s Secret

```bash
kubectl patch secret homelab-auth-secrets -n apps \
  --type merge \
  -p '{"stringData":{"my-new-client-secret":"'"${CLIENT_SECRET_ENCODED}"'"}}'
```

### Step 3: Add Client Configuration

Edit `application.yaml` and add to `app.oidc.clients`:

```yaml
app:
  oidc:
    clients:
      - client-id: my-new-client
        client-secret: "${MY_NEW_CLIENT_SECRET}"
        redirect-uris:
          - "https://my-new-client.furchert.ch/login/oauth2/code/my-new-client"
        post-logout-redirect-uris:
          - "https://my-new-client.furchert.ch"
        scopes: [openid, profile, email]
```

### Step 4: Reference Secret in Deployment

Add to `k8s/deployment.yaml`:

```yaml
env:
  - name: MY_NEW_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: homelab-auth-secrets
        key: my-new-client-secret
```

### Step 5: Restart Service

```bash
kubectl rollout restart deployment/auth-service -n apps
kubectl rollout status deployment/auth-service -n apps
```

### Step 6: Configure Client Application

Provide the client with:
- **Client ID:** `my-new-client`
- **Client Secret:** The **plaintext** secret (without `{noop}` or `{bcrypt}` prefix)
- **Discovery URL:** `https://auth.furchert.ch/.well-known/openid-configuration`

---

## 7. Cluster-Internal Access Patterns

### From Other Pods in `apps` Namespace

Access auth-service using the Kubernetes DNS name:

```
http://auth-service.apps.svc.cluster.local:8080
```

### From Other Namespaces

```
http://auth-service.apps.svc.cluster.local:8080
```

### Service Account Requirements

No special ServiceAccount is required. The auth-service does not use network policies.

---

## 8. IoT Device Clients (client_credentials)

IoT devices authenticate to Mosquitto with a short-lived JWT obtained from the
token endpoint using the OAuth2 **`client_credentials`** grant. Each device is
represented by its own registered client (`client_kind = 'device'`), created
and revoked through an internal admin API. This API is **admin-only** and not
part of the public OIDC surface.

### Admin API — Device Client Lifecycle

**Base URL:** `https://auth.furchert.ch/api/v1/clients`
(cluster-internal: `http://auth-service.apps.svc.cluster.local:8080/api/v1/clients`)

**Authorization:** a JWT with role `ADMIN`, **or** a client token carrying the
`clients:admin` scope (this is how `device-service` calls it service-to-service).

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/api/v1/clients` | `{ "clientId": "terra1", "description": "Greenhouse terrarium 1" }` | `201` — created client with one-time secret |
| `GET` | `/api/v1/clients` | — | `200` — list of device clients (`client_kind='device'` only) |
| `GET` | `/api/v1/clients/{clientId}` | — | `200` single client, or `404` |
| `DELETE` | `/api/v1/clients/{clientId}` | — | `204` (idempotent) — see revocation note below |

`clientId` must match `[a-z0-9-]{3,32}` (also the device's MQTT username).
`description` is optional, max 200 chars.

**Create response** (`201`) — the `clientSecret` is plaintext and returned
**exactly once**; it is stored only as a bcrypt hash and cannot be retrieved
again:

```json
{
  "clientId": "terra1",
  "clientSecret": "8f3k...Base64URL...",
  "scopes": ["mqtt:pub", "mqtt:sub"],
  "createdAt": "2026-05-16T10:00:00Z"
}
```

**List / get response:**

```json
{
  "clientId": "terra1",
  "description": "Greenhouse terrarium 1",
  "createdAt": "2026-05-16T10:00:00Z",
  "scopes": ["mqtt:pub", "mqtt:sub"]
}
```

**Delete:** removes the client from `oauth2_registered_client` and deletes its
outstanding `oauth2_authorization` rows, so new token requests fail
immediately. JWTs already issued to the device remain valid at Mosquitto until
their `exp` (see revocation note in *Important Notes*).

### Requesting a Device Token

```bash
curl -u terra1:<clientSecret> \
  -d 'grant_type=client_credentials' \
  https://auth.furchert.ch/oauth2/token
```

Response — a 1-hour access token, **no refresh token** (devices
re-authenticate on expiry):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "mqtt:pub mqtt:sub"
}
```

### Device Token Claims

`client_credentials` tokens for device clients carry a `device_id` claim (the
`clientId`) and **no `role` claim**. Mosquitto's JWT plugin uses `device_id`
as the MQTT username for ACL evaluation, and validates the signature via
`/oauth2/jwks` like any other token.

```json
{
  "sub": "terra1",
  "aud": "terra1",
  "scope": "mqtt:pub mqtt:sub",
  "device_id": "terra1",
  "iss": "https://auth.furchert.ch",
  "iat": 1714234567,
  "exp": 1714238167
}
```

---

## Important Notes

1. **Single-Pod Limitation:** auth-service runs as a single pod (replicas: 1) because Spring Authorization Server stores sessions in memory. Scaling to multiple replicas requires adding Spring Session with Redis/PostgreSQL backend.

2. **Token Expiry:** Access tokens expire after 15 minutes, refresh tokens after 7 days. Clients must implement token refresh logic.

3. **Session Management:** The OIDC login flow uses cookie-based sessions. The User CRUD API uses stateless JWT tokens.

4. **Key Rotation:** When RSA keys are rotated, all existing tokens become invalid immediately. Downstream services must fetch the new JWKS.

5. **No Rate Limiting:** Currently, there is no rate limiting on any endpoints. Consider adding if exposed to untrusted networks.

6. **Device Token Revocation:** Deleting a device client (or its outstanding authorizations) stops *new* tokens from being issued, but JWTs already held by a device stay valid at Mosquitto until their `exp` (1-hour TTL). Immediate revocation of outstanding device tokens requires signing-key rotation.

7. **RP-Initiated Logout Failure Mode:** An unresolvable `id_token_hint` (purged authorization, `sid` mismatch) only ends the IdP's local session and redirects to `/login?logout` when the hint is a token signed by this server — even if expired or already purged. Any other hint (missing, forged, garbage) gets the standard `400 invalid_token` error page and no session change, so a cross-site link cannot force a logout.
