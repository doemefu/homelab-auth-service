# Changelog

## [Unreleased]

### Breaking

- Direct auth API (`/api/v1/auth/**`) removed — login, refresh, logout, and JWKS are no longer served at these paths. Downstream services must update to the OIDC endpoints.

### Added

- OIDC Identity Provider via Spring Authorization Server — SSO for all furchert.ch homelab services
- Authorization Code Flow with PKCE (`/oauth2/authorize`, `/oauth2/token`)
- OIDC discovery document at `/.well-known/openid-configuration`
- Login page at `/login` (form-based authentication)
- JWKS endpoint at `/oauth2/jwks` (replaces `/api/v1/auth/jwks`)
- UserInfo endpoint at `/userinfo`
- RP-Initiated Logout at `/connect/logout`
- Pre-configured OIDC clients: `grafana`, `homeassistant`, `device-service`, `n8n`
- Flyway V3 migration: creates `oauth2_authorization` and `oauth2_authorization_consent` tables for Spring Authorization Server
- Flyway V4 migration: drops legacy `refresh_tokens` table
- Flyway V5 migration: creates `oauth2_registered_client` (Spring AS JDBC schema) with extension column `client_kind VARCHAR(20) NOT NULL DEFAULT 'sso'`
- `StaticClientSeeder` — idempotent one-shot bootstrap of YAML-defined SSO clients into the new `oauth2_registered_client` table on first boot
- Admin REST API `POST/GET/DELETE /api/v1/clients` for IoT device client lifecycle, gated by `hasRole('ADMIN') or hasAuthority('SCOPE_clients:admin')`
- `device_id` JWT claim emitted on `client_credentials` access tokens where `client_kind='device'` (consumed by Mosquitto JWT plugin)
- `ResourceConflictException` → HTTP 409; `AuthorizationDeniedException`/`AccessDeniedException` → HTTP 403 in `GlobalExceptionHandler`
- `@EnableMethodSecurity` enabled globally on `SecurityConfig` so `@PreAuthorize` works on controllers
- `app.oidc.device-clients.access-token-ttl-seconds` (default 3600) and `allowed-scopes` config properties

### Changed

- Token storage migrated from `refresh_tokens` table to `oauth2_authorization` table (Flyway V3)
- `TokenCleanupScheduler` now purges expired `oauth2_authorization` records (was: `refresh_tokens`)
- `server.forward-headers-strategy=native` required for correct issuer URL behind reverse proxy
- Username change and password reset now revoke all active OAuth2 authorizations, requiring re-authentication
- `PasswordEncoder` switched to `DelegatingPasswordEncoder` to support `{noop}`/`{bcrypt}` prefixes for OIDC client secrets
- API filter chain is now stateless (no sessions); login form uses a separate stateful filter chain
- OIDC client secret env vars must include the Spring Security `{id}` prefix (e.g. `{noop}secret`)
- Registered clients moved from in-memory to JDBC (`oauth2_registered_client`); after first boot, YAML edits to client definitions are no-ops — manage via `psql` or `/api/v1/clients`
- `device-service` OIDC client extended to multi-grant (`authorization_code` + `refresh_token` + `client_credentials`) with new `clients:admin` scope (for service-to-service calls to `/api/v1/clients`)
- `JwtAuthenticationConverter` now emits both `ROLE_*` (from `role` claim) and `SCOPE_*` (from `scope` claim) authorities

### Removed

- jjwt dependency (`io.jsonwebtoken:jjwt-*`)
- `RefreshToken` entity and `RefreshTokenRepository`
- `JwtService`, `JwtAuthenticationFilter`
- Proprietary `TokenCleanupScheduler` (replaced by a new scheduler purging `oauth2_authorization`)
- Proprietary auth endpoints: `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/jwks`

---

## [0.1.0] — Initial release

### Added
- Initial implementation of homelab-auth-service
- JWT issuance and refresh using jjwt 0.12.6 + RSA key pair
- JWKS endpoint (`GET /api/v1/auth/jwks`) for downstream service token validation
- User CRUD: create, get, update, delete (`/api/v1/users`)
- Password reset with current-password verification for self-service
- Role-based access control: `USER`, `ADMIN`
- API versioning: all endpoints under `/api/v1/`
- Flyway V1 schema migration (users + refresh_tokens tables)
- Refresh token rotation on every refresh — DB-backed, revocable
- Logout invalidates all refresh tokens for the user
- Spring Boot 4.0.5 / Java 25 / Spring Security 7
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`)
- K8s manifests (Deployment + Service, namespace `apps`)
- GitHub Actions CI: test + multi-arch build/push to ghcr.io

### Changed
- Refresh tokens are now SHA-256 hashed before database storage (breaking: existing tokens invalidated)
- JWKS endpoint includes `kid: "auth-service-v1"`; JWT headers now carry `kid`
- All timestamps migrated from `LocalDateTime` to `Instant` (`TIMESTAMPTZ` in PostgreSQL)
- `password_hash` column widened to `VARCHAR(255)`
- `refresh_tokens.token` column resized to `VARCHAR(64)` for SHA-256 hex strings
- K8s deployment image tag changed from `:latest` to `:<SHA>` placeholder
- Username changes and password resets now invalidate all refresh tokens for the user
- Unified error response format: filter-chain 401/403 and service-layer exceptions use consistent JSON shape

### Added
- `TokenCleanupScheduler`: expired refresh tokens are automatically purged every hour
- Service-layer validation for roles (`USER`/`ADMIN` only) and status (`ACTIVE`/`INACTIVE` only)
- `AccessDeniedException` and `BadCredentialsException` handlers in `GlobalExceptionHandler`
- Flyway V2 migration for schema changes above
