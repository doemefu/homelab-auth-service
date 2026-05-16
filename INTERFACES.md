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
| Client Credentials | ❌ No | Not supported |
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
- **Liveness Probe:** `GET /actuator/health` (30s initial delay, 10s period, 3 failures)
- **Readiness Probe:** `GET /actuator/health` (20s initial delay, 5s period, 3 failures)

---

## 6. Configure a New OIDC Client

To add a new OIDC client to auth-service:

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

## Important Notes

1. **Single-Pod Limitation:** auth-service runs as a single pod (replicas: 1) because Spring Authorization Server stores sessions in memory. Scaling to multiple replicas requires adding Spring Session with Redis/PostgreSQL backend.

2. **Token Expiry:** Access tokens expire after 15 minutes, refresh tokens after 7 days. Clients must implement token refresh logic.

3. **Session Management:** The OIDC login flow uses cookie-based sessions. The User CRUD API uses stateless JWT tokens.

4. **Key Rotation:** When RSA keys are rotated, all existing tokens become invalid immediately. Downstream services must fetch the new JWKS.

5. **No Rate Limiting:** Currently, there is no rate limiting on any endpoints. Consider adding if exposed to untrusted networks.
