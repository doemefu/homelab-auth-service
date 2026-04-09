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
- Pre-configured OIDC clients: `grafana`, `home-assistant`
- Flyway V3 migration: creates `oauth2_authorization` and `oauth2_authorization_consent` tables for Spring Authorization Server
- Flyway V4 migration: drops legacy `refresh_tokens` table

### Changed

- Token storage migrated from `refresh_tokens` table to `oauth2_authorization` table (Flyway V3)
- `TokenCleanupScheduler` now purges expired `oauth2_authorization` records (was: `refresh_tokens`)
- `server.forward-headers-strategy=native` required for correct issuer URL behind reverse proxy
- Username change and password reset now revoke all active OAuth2 authorizations, requiring re-authentication
- `PasswordEncoder` switched to `DelegatingPasswordEncoder` to support `{noop}`/`{bcrypt}` prefixes for OIDC client secrets
- API filter chain is now stateless (no sessions); login form uses a separate stateful filter chain
- OIDC client secret env vars must include the Spring Security `{id}` prefix (e.g. `{noop}secret`)

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
