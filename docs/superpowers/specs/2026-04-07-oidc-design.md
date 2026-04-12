# OIDC Identity Provider — Design Spec

**Date:** 2026-04-07  
**Service:** homelab-auth-service  
**Status:** Approved

---

## Goal

Extend homelab-auth-service into a fully spec-compliant OIDC Identity Provider so that any furchert.ch homelab service (Grafana, Home Assistant, Portainer, Gitea, etc.) can use it for Single Sign-On via the standard OAuth2 Authorization Code Flow.

---

## Background

The service currently issues custom RSA-signed JWTs via a proprietary login API (`POST /api/v1/auth/login`). No external services are consuming this API. The goal is to replace it with a standards-based OIDC implementation so off-the-shelf services can integrate without custom code.

---

## Approach

Use **Spring Authorization Server** (`spring-security-oauth2-authorization-server`) — the official Spring Security project for OAuth2/OIDC. It is spec-compliant, battle-tested, and integrates directly with the existing `User` entity, `CustomUserDetailsService`, and RSA key pair.

**New dependencies (approved):**
- `spring-boot-starter-oauth2-authorization-server` (BOM-managed by Spring Boot 4.0.5)
- `spring-boot-starter-thymeleaf`

---

## Architecture

### Two Security Filter Chains

| Chain | Order | Handles | Session policy |
|---|---|---|---|
| Authorization Server | 1 (highest) | `/oauth2/**`, `/.well-known/**`, `/login`, `/userinfo` | Session-based (required for auth code flow) |
| Resource Server | 2 | `/api/v1/**`, `/actuator/**` | Stateless, bearer token |

CSRF is enabled for the login form (session-based). CSRF remains disabled for `/api/v1/**`.

### URL Layout

```
# OIDC endpoints (spec-mandated paths, no versioning)
GET  /.well-known/openid-configuration   # discovery
GET  /oauth2/authorize                   # start auth code flow
POST /oauth2/token                       # exchange code → tokens
GET  /oauth2/jwks                        # public key
GET  /userinfo                           # user claims
POST /oauth2/revoke                      # token revocation
GET  /connect/logout                     # OIDC RP-Initiated Logout (Single Sign-Out)
GET  /login                              # HTML login form
POST /login                              # form submit

# Admin API (versioned)
GET/POST/PUT/DELETE /api/v1/users/**     # user management (ADMIN role required)
```

---

## Components

### New Files

| File | Purpose |
|---|---|
| `config/AuthorizationServerConfig.java` | Spring AS setup: registered clients, token settings, `JwtEncoder` wired to existing RSA keys, OIDC userinfo config, RP-Initiated Logout (`/connect/logout`) |
| `config/OidcClientProperties.java` | `@ConfigurationProperties(prefix="app.oidc")` — loads client list from `application.yaml` |
| `security/OidcUserInfoMapper.java` | Maps `User` → OIDC claims: `sub` (username), `email`, `preferred_username`, `roles` |
| `templates/login.html` | Minimal Thymeleaf login form with CSRF token and error/logout messages |
| `db/migration/V3__oauth2_authorization_schema.sql` | Spring AS JDBC tables: `oauth2_authorization`, `oauth2_authorization_consent` |

### Modified Files

| File | Change |
|---|---|
| `config/SecurityConfig.java` | Rewrite: two filter chains (AS chain + resource server chain); remove custom JWT filter wiring |
| `resources/application.yaml` | Add `app.oidc.issuer`, `app.oidc.clients[]`; add env var references for client secrets |

### Deleted Files

| File | Reason |
|---|---|
| `controller/AuthController.java` | All endpoints replaced by Spring AS |
| `service/AuthService.java` | Logic absorbed into Spring AS + `OidcUserInfoMapper` |
| `security/JwtAuthenticationFilter.java` | Replaced by Spring AS resource server support |
| `security/JwtService.java` | Spring AS handles token generation |
| `entity/RefreshToken.java` | Spring AS manages token storage via `oauth2_authorization` table |
| `repository/RefreshTokenRepository.java` | |
| `service/TokenCleanupScheduler.java` | Replaced by updated scheduler that purges `oauth2_authorization` table (see note below) |
| `dto/LoginRequest.java` | |
| `dto/LoginResponse.java` | |
| `dto/RefreshRequest.java` | |

**Stays untouched:** `UserService`, `UserRepository`, `User`, `CustomUserDetailsService`, `RsaKeyProvider`, `GlobalExceptionHandler`, user DTOs.

**`UserController`** is modified: `@AuthenticationPrincipal String username` → `@AuthenticationPrincipal(expression = "subject") String username` in `getUser` and `resetPassword` methods (JWT resource server principal is `Jwt`, not `String`).

**`RsaKeyProperties`** stays and is reused: its `accessTokenExpiry` and `refreshTokenExpiry` values are read by `AuthorizationServerConfig` when configuring Spring AS `TokenSettings`. The `privateKey` / `publicKey` paths are reused by `RsaKeyProvider` as today.

**`TokenCleanupScheduler`** is rewritten (not deleted): `JdbcOAuth2AuthorizationService` does not auto-purge expired rows. The scheduler is updated to delete expired rows from `oauth2_authorization` instead of the old `refresh_tokens` table.

---

## Data Flow — Authorization Code Flow with PKCE

```
1. User visits Grafana → clicks "Sign in"

2. Grafana redirects browser →
   GET /oauth2/authorize
     ?client_id=grafana
     &response_type=code
     &redirect_uri=https://grafana.furchert.ch/login/generic_oauth
     &scope=openid profile email
     &state=<random>
     &code_challenge=<PKCE challenge>
     &code_challenge_method=S256

3. No session → Spring AS redirects → GET /login

4. User submits credentials:
   POST /login  {username, password, _csrf}

5. Spring Security authenticates via CustomUserDetailsService
   → session created → redirect back to /oauth2/authorize

6. Spring AS issues short-lived auth code → redirect to client:
   https://grafana.furchert.ch/login/generic_oauth?code=ABC&state=<random>

7. Grafana back-channel (server → server):
   POST /oauth2/token
     code=ABC
     &grant_type=authorization_code
     &code_verifier=<PKCE verifier>
     &client_id=grafana
     &client_secret=<secret>

8. Spring AS validates code + PKCE verifier → returns:
   {
     "access_token":  "<RSA-signed JWT, 15 min>",
     "id_token":      "<RSA-signed JWT with sub, email, preferred_username>",
     "refresh_token": "<opaque token, 7 days>",
     "token_type":    "Bearer",
     "expires_in":    900
   }

9. Grafana optionally: GET /userinfo (Bearer access_token)
   → { "sub": "dominic", "email": "...", "preferred_username": "dominic", "roles": ["USER"] }

10. User is logged in to Grafana.
```

---

## Token Infrastructure

- **Signing:** Spring AS `JwtEncoder` wired to existing `private.pem` via `RsaKeyProvider`
- **Key ID:** `auth-service-v1` (unchanged)
- **JWKS:** `/oauth2/jwks` exposes the same RSA public key as the previous `/api/v1/auth/jwks`
- **Access token lifetime:** 15 min (900 000 ms — matches `app.jwt.access-token-expiry`)
- **Refresh token lifetime:** 7 days (matches `app.jwt.refresh-token-expiry`)
- **Auth code lifetime:** 5 min
- **Token storage:** `JdbcOAuth2AuthorizationService` — persisted in `oauth2_authorization` table

---

## Client Registration

Defined in `application.yaml`, loaded via `OidcClientProperties`, registered as `InMemoryRegisteredClientRepository`:

```yaml
app:
  oidc:
    issuer: https://auth.furchert.ch
    clients:
      - client-id: grafana
        client-secret: "${GRAFANA_CLIENT_SECRET}"
        redirect-uris:
          - https://grafana.furchert.ch/login/generic_oauth
        scopes: [openid, profile, email]
      - client-id: homeassistant
        client-secret: "${HA_CLIENT_SECRET}"
        redirect-uris:
          - https://ha.furchert.ch/auth/oidc/callback
        scopes: [openid, profile, email]
```

- Client secrets are stored as pre-hashed BCrypt strings in env vars (e.g. `{bcrypt}$2a$10$...`) — never raw secrets, never runtime hashing at startup
- Each client gets: Authorization Code + PKCE, Refresh Token grant, `requireAuthorizationConsent(false)` (first-party apps)
- No implicit grant, no client credentials grant

**To add a new client:** add an entry to `app.oidc.clients`, set the env var, restart the service.

---

## Login Page

Minimal Thymeleaf template — no external CSS, self-contained, functional:

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>furchert.ch — Sign in</title></head>
<body>
  <h1>Sign in</h1>
  <div th:if="${param.error}">Invalid username or password.</div>
  <div th:if="${param.logout}">You have been signed out.</div>
  <form method="post" action="/login">
    <input type="text"     name="username" placeholder="Username" required />
    <input type="password" name="password" placeholder="Password" required />
    <input type="hidden"   th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
```

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| Wrong credentials | Redirect to `/login?error` (Spring Security standard) |
| User logs out of a client (e.g. Grafana) | Client sends `id_token_hint` to `GET /connect/logout` → AS terminates session → redirects to `post_logout_redirect_uri` |
| Invalid client / bad redirect URI | RFC 6749 JSON error: `{"error":"invalid_client"}` |
| Expired/invalid bearer token on `/api/v1/**` | 401 JSON via existing `GlobalExceptionHandler` |
| Unknown user at `/userinfo` | 401 |

---

## Testing Approach

**Test-driven development** — tests written before implementation code.

| Layer | What to test |
|---|---|
| Unit | `OidcUserInfoMapper` — claim mapping for USER and ADMIN roles; `OidcClientProperties` — config loading and BCrypt hashing |
| Integration (Testcontainers) | Full Authorization Code Flow via MockMvc; `/oauth2/token` exchange; `/userinfo` claims; `/oauth2/jwks` public key; `/api/v1/users` protected by bearer token; invalid credentials → 401 |

Existing `UserController` integration tests stay unchanged.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Spring Authorization Server version incompatible with SB 4.0.5 / Spring Security 7.0 | Medium | High | Verify version during Phase 3 (plan) before writing any code; check context7 docs |
| `JdbcOAuth2AuthorizationService` does not auto-purge expired tokens | Certain | Medium | `TokenCleanupScheduler` rewritten to purge `oauth2_authorization` table |
| Single-pod session constraint: in-memory HTTP sessions break if service is scaled beyond 1 replica | Low (homelab) | High (if scaled) | Accepted risk for single-pod K3s deployment; explicitly documented in DEPLOYMENT.md; session store (e.g. Redis) required before any horizontal scaling |
| `/oauth2/token` back-channel blocked by CSRF if filter chain `requestMatchers` overlap | Low | High | Resource server chain scoped strictly to `/api/v1/**` and `/actuator/**`; Spring AS chain handles all `/oauth2/**`; verified in integration tests |
| Session-based AS chain conflicts with stateless API chain | Low | Medium | Enforce chain ordering; test both chains in integration tests |
| BCrypt hashing of client secrets at startup adds latency | Low | Low | Use cost factor 10 (default); acceptable at startup |
| Existing K8s `Deployment` env vars don't include new `*_CLIENT_SECRET` vars | Medium | Medium | Document in DEPLOYMENT.md; update K8s secret before deploy |

---

## Documentation Updates Required

| File | Update |
|---|---|
| `README.md` | Replace auth API section with OIDC IdP section; add discovery URL; quick-start for integrating a new service |
| `OPERATIONS.md` | How to add a new OIDC client; how to rotate a client secret; token lifetime config |
| `CONTRIBUTING.md` | Updated local dev setup (login flow instead of direct API calls) |
| `DEPLOYMENT.md` | New env vars for each client secret; K8s Secret updates |
| `CHANGELOG.md` | Breaking change note (direct auth API removed) |

A dedicated **"Integrating a service with furchert.ch SSO"** section in `OPERATIONS.md` will include:
- Generic OIDC config values (discovery URL, client ID/secret, scopes)
- Step-by-step worked example for Grafana
- Step-by-step worked example for Home Assistant
- Template config snippet reusable for other services
