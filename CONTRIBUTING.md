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
- **`@WithMockUser` does not work** with `STATELESS` session policy and Spring Security 7's `SecurityContextHolderFilter`. Use `SecurityMockMvcRequestPostProcessors.user(...).roles(...)` as a request post-processor instead. For endpoints that resolve `@AuthenticationPrincipal String username`, use `authentication(new UsernamePasswordAuthenticationToken("username", ...))` so the principal is a plain `String` (matching what `JwtAuthenticationFilter` sets in production)
- **`JwtAuthenticationFilter` must not be mocked** in `@WebMvcTest` — mock `JwtService` instead. `OncePerRequestFilter.doFilter()` is `final` so Mockito cannot intercept it; mocking the filter breaks the entire filter chain

---

## Database Migrations

All schema changes go through Flyway. Migration files are in `src/main/resources/db/migration/` and follow `V{n}__{description}.sql` (two underscores).

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
