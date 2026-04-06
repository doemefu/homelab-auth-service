# Changelog

## [Unreleased]

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
