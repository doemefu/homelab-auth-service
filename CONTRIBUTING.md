# CONTRIBUTING.md — homelab-auth-service

---

## Prerequisites

- Java 25 (Temurin distribution recommended — matches CI)
- Docker Desktop or Docker Engine running locally (required for Testcontainers integration tests)
- kubectl configured to reach the homelab K3s cluster (for port-forwarding the database during local dev)
- No separate Maven installation needed — use the included `./mvnw` wrapper

---

## Local Development Setup

### 1. Generate test RSA keys (one-time)

```bash
mkdir -p src/test/resources/keys
openssl genrsa -out src/test/resources/keys/private.pem 2048
openssl rsa -in src/test/resources/keys/private.pem -pubout -out src/test/resources/keys/public.pem
```

These are for tests only. Never commit them — `src/test/resources/keys/` is in `.gitignore`.

### 2. Port-forward PostgreSQL from the cluster

```bash
kubectl port-forward -n apps svc/postgres 5432:5432
```

### 3. Set environment variables and run

```bash
export DB_USERNAME=homelab
export DB_PASSWORD=homelab
./mvnw spring-boot:run
```

The service connects to database `homelabdb` on `localhost:5432` (default in `application.yaml`).

---

## Running Tests

```bash
# Unit + controller tests — no Docker required
./mvnw test

# Full suite including Testcontainers integration tests — Docker must be running
./mvnw verify

# Single test class
./mvnw test -Dtest=AuthServiceTest
```

---

## Test with OIDC Flow

To exercise the full OIDC login flow locally:

1. Port-forward PostgreSQL from the cluster (see step 2 in Local Development Setup).

2. Set env vars and start the service:
   ```bash
   export DB_USERNAME=homelab
   export DB_PASSWORD=homelab
   export GRAFANA_CLIENT_SECRET="{noop}local-dev-secret"
   export HA_CLIENT_SECRET="{noop}local-dev-secret"
   ./mvnw spring-boot:run
   ```

> The `{noop}` prefix is required: Spring Security's `DelegatingPasswordEncoder` uses it to select the password encoder. Without the prefix, the stored secret is treated as BCrypt and OIDC client authentication at `/oauth2/token` will fail.

3. Open `http://localhost:8080/login` in your browser. You should see the login page.

4. Log in with a user that exists in the cluster database. On success, Spring Authorization Server issues an authorization code and redirects to the configured redirect URI.

5. To test the discovery document:
   ```bash
   curl -s http://localhost:8080/.well-known/openid-configuration | python3 -m json.tool
   ```

6. To test the JWKS endpoint:
   ```bash
   curl -s http://localhost:8080/oauth2/jwks | python3 -m json.tool
   ```

> **Note:** The `app.oidc.issuer` value in `application.yaml` must be set to `http://localhost:8080` for local testing. In cluster deployments it must match the public ingress URL exactly.

---

## Test Structure

| Location | Type | Dependencies |
|----------|------|-------------|
| `src/test/.../service/` | Unit tests (Mockito) | None |
| `src/test/.../controller/` | MockMvc slice tests (`@WebMvcTest`) | None |
| `src/test/.../integration/` | Integration tests (Testcontainers) | Docker |

`AbstractIntegrationTest` provides a shared `PostgreSQLContainer("postgres:17-alpine")` for all integration tests via `@DynamicPropertySource`.

---

## Spring Boot 4.0 / Spring Security 7 Notes

- **Jackson 3** uses group ID `tools.jackson` (not `com.fasterxml.jackson`) — import `tools.jackson.databind.ObjectMapper` in tests
- **`@WebMvcTest`** support moved to the `spring-boot-webmvc-test` artifact
- **`SecurityConfig` must be explicitly `@Import`ed** in `@WebMvcTest` tests — it is no longer auto-scanned by the web slice
- **`@WithMockUser` is not the right fit for JWT-protected endpoints** with the current OAuth2 Resource Server setup. Use `SecurityMockMvcRequestPostProcessors.jwt()` to attach an authenticated JWT to the request. For endpoints that resolve `@AuthenticationPrincipal Jwt jwt` or read claims, configure those claims on the `jwt()` post-processor.
- **Do not mock a removed custom JWT filter/service in `@WebMvcTest`** — the service now relies on Spring Security's OAuth2 Resource Server. If a test needs JWT decoding to succeed, provide or mock a `JwtDecoder` bean in the test context; if it only needs an authenticated request, prefer `jwt()` and skip token parsing altogether.
- **Timestamps** — all entity timestamps use `java.time.Instant` (mapped to PostgreSQL `TIMESTAMPTZ`). Do not use `LocalDateTime` for any new timestamp fields.
- **OAuth2 storage** — Spring Authorization Server persists tokens in the `oauth2_authorization` table (Flyway V3). Do not reference the old `refresh_tokens` table in new code or tests.

---

## Database Migrations

All schema changes go through Flyway. Migration files are in `src/main/resources/db/migration/` and follow `V{n}__{description}.sql` (two underscores).

Current migrations:
- **V1** — Initial schema: `users` + `refresh_tokens` tables
- **V2** — Widens `password_hash` to `VARCHAR(255)`, resizes `refresh_tokens.token` to `VARCHAR(64)` for SHA-256 hashes, converts all timestamps to `TIMESTAMPTZ`
- **V3** — Creates `oauth2_authorization` and `oauth2_authorization_consent` tables for Spring Authorization Server token storage
- **V4** — Drops legacy `refresh_tokens` table

New migrations should follow `V5__description.sql`.

Never edit or delete an existing migration file — Flyway checksums will fail on next startup.

The Flyway history table is named `flyway_schema_history_auth` to avoid conflicts when multiple services share the same PostgreSQL instance.

---

## CI/CD

GitHub Actions workflow: `.github/workflows/build.yml`

- Every push and PR to `main` runs `./mvnw verify` (includes integration tests)
- On push to `main` (after tests pass): multi-arch Docker image built (`linux/amd64` + `linux/arm64`) and pushed to `ghcr.io/doemefu/homelab-auth-service:<git-sha>`

---

## Pull Request Process

- All changes go through a PR to `main`
- CI must be green (all tests pass) before merging
- Keep diffs minimal — no drive-by refactors or style-only changes
- New features require unit tests; database-touching features require integration tests
- All comments and documentation must be in English
