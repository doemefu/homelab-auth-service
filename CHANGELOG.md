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
