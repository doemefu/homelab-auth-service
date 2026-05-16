# homelab-auth-service — Development Guide

This document provides instructions, reminders, and useful reference for developers and agents working on this repository.

---

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Java | 25 (Temurin recommended) | Runtime |
| Maven | 3.9+ (via `./mvnw` wrapper) | Build tool |
| Docker | Desktop or Engine | Integration tests (Testcontainers) |
| kubectl | latest | Local development (DB port-forwarding) |
| OpenSSL | latest | RSA key generation |
| htpasswd | latest | BCrypt hash generation |
| Git | latest | Version control |

**Note:** No separate Maven installation is needed — use the included `./mvnw` wrapper.

### Optional Tools

| Tool | Purpose |
|------|---------|
| jq | JSON pretty-printing |
| curl | API testing |
| PostgreSQL CLI | Database inspection |

---

## Project Structure

```
homelab-auth-service/
├── src/main/java/ch/furchert/homelab/auth/
│   ├── config/              # Spring configuration classes
│   │   ├── AuthorizationServerConfig.java  # OIDC server config
│   │   ├── SecurityConfig.java             # Security filter chains
│   │   ├── OidcClientProperties.java       # OIDC client properties
│   │   └── RsaKeyProperties.java           # JWT key properties
│   │
│   ├── controller/          # REST API controllers
│   │   ├── UserController.java              # User CRUD endpoints
│   │   └── LoginController.java             # Login page
│   │
│   ├── dto/                 # Data transfer objects
│   │   ├── CreateUserRequest.java
│   │   ├── UpdateUserRequest.java
│   │   ├── ResetPasswordRequest.java
│   │   └── UserResponse.java
│   │
│   ├── entity/              # JPA entities
│   │   ├── User.java                        # User entity
│   │   └── Role.java                        # Role enum
│   │
│   ├── exception/           # Exception handling
│   │   ├── ResourceNotFoundException.java
│   │   └── GlobalExceptionHandler.java
│   │
│   ├── repository/          # Spring Data JPA repositories
│   │   └── UserRepository.java
│   │
│   ├── security/            # Security utilities
│   │   ├── RsaKeyProvider.java
│   │   ├── OidcUserInfoMapper.java
│   │   └── CustomUserDetailsService.java
│   │
│   ├── service/             # Business logic
│   │   ├── UserService.java
│   │   └── TokenCleanupScheduler.java
│   │
│   └── AuthServiceApplication.java        # Main application class
│
├── src/main/resources/
│   ├── application.yaml                    # Main configuration
│   ├── db/migration/                       # Flyway migrations
│   │   ├── V1__init.sql
│   │   ├── V2__timestamps_to_timestamptz_and_fixes.sql
│   │   ├── V3__oauth2_authorization_schema.sql
│   │   └── V4__drop_refresh_tokens.sql
│   │
│   └── templates/                         # Thymeleaf templates
│       └── login.html
│
├── src/test/                              # Tests
│   ├── .../service/                       # Unit tests
│   ├── .../controller/                    # MockMvc slice tests
│   └── .../integration/                   # Testcontainers integration tests
│
├── k8s/                                  # Kubernetes manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   └── kustomization.yaml
│
├── .github/workflows/                    # GitHub Actions
│   └── build.yml
│
├── docs/                                 # Documentation
│   ├── OVERVIEW.md
│   ├── INTERFACES.md
│   ├── DEVELOPMENT.md (this file)
│   └── DEPLOYMENT.md
│
└── pom.xml                               # Maven configuration
```

---

## Local Development Setup

### 1. Clone and Initialize

```bash
# Clone the repository
git clone git@github.com:doemefu/homelab-auth-service.git
cd homelab-auth-service

# Switch to dev branch (optional - main is also fine)
git checkout dev
```

### 2. Generate RSA Keys

The service requires RSA key pairs for JWT signing. Generate separate keys for main and test:

```bash
# Main keys (for local development)
mkdir -p src/main/resources/keys
openssl genrsa -out src/main/resources/keys/private.pem 2048
openssl rsa -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem

# Test keys
mkdir -p src/test/resources/keys
openssl genrsa -out src/test/resources/keys/private.pem 2048
openssl rsa -in src/test/resources/keys/private.pem -pubout -out src/test/resources/keys/public.pem
```

**IMPORTANT:** Never commit these files. Both `src/main/resources/keys/` and `src/test/resources/keys/` are in `.gitignore`. For cluster deployment, keys are injected via the `homelab-auth-rsa-keys` K8s Secret.

### 3. Port-Forward PostgreSQL

The service expects a PostgreSQL database at `localhost:5432` with database name `homelabdb`.

```bash
# Port-forward the cluster PostgreSQL service
kubectl port-forward -n apps svc/postgresql 5432:5432
```

**Note:** Some older documentation may reference `svc/postgres`. Use the service name that exists in your cluster. For this setup, it's `svc/postgresql`.

### 4. Set Environment Variables

```bash
# Database credentials
export DB_USERNAME=homelab
export DB_PASSWORD=homelab

# OIDC issuer (must match what clients use)
export APP_OIDC_ISSUER=http://localhost:8080

# OIDC client secrets (for local testing)
export GRAFANA_CLIENT_SECRET="{noop}local-dev-secret"
export HA_CLIENT_SECRET="{noop}local-dev-secret"
export DEVICE_SERVICE_CLIENT_SECRET="{noop}local-dev-secret"
export N8N_CLIENT_SECRET="{noop}local-dev-secret"
export LITELLM_CLIENT_SECRET="{noop}local-dev-secret"
```

**IMPORTANT:** The `{noop}` prefix is **required**. Spring Security's `DelegatingPasswordEncoder` uses it to select the password encoder. Without it, the stored secret is treated as BCrypt and OIDC client authentication at `/oauth2/token` will fail.

### 5. Run the Service

```bash
# Using the Maven wrapper
./mvnw spring-boot:run

# Or with native Maven
export MAVEN_OPTS="-Xmx1g"
mvn spring-boot:run
```

The service will start on `http://localhost:8080`.

### 6. Verify it Works

```bash
# Check health
curl -s http://localhost:8080/actuator/health

# Check OIDC discovery
curl -s http://localhost:8080/.well-known/openid-configuration | jq

# Check JWKS
curl -s http://localhost:8080/oauth2/jwks | jq
```

---

## Running Tests

### Unit Tests (No Docker Required)

```bash
# Run only unit tests
./mvnw test

# Run a specific test class
./mvnw test -Dtest=UserServiceTest

# Run tests for a specific package
./mvnw test -Dtest='ch.furchert.homelab.auth.service.*'
```

### Integration Tests (Docker Required)

```bash
# Run full suite including Testcontainers integration tests
./mvnw verify

# Run only integration tests
./mvnw test -Dtest='*IntegrationTest'
```

### Test Structure

| Location | Type | Dependencies | Execution Time |
|----------|------|--------------|----------------|
| `src/test/.../service/` | Unit tests (Mockito) | None | ~1-5 seconds |
| `src/test/.../controller/` | MockMvc slice tests (@WebMvcTest) | None | ~5-10 seconds |
| `src/test/.../integration/` | Integration tests (Testcontainers) | Docker | ~30-60 seconds each |

**Note:** `AbstractIntegrationTest` provides a shared `PostgreSQLContainer("postgres:17-alpine")` for all integration tests via `@DynamicPropertySource`.

### Spring Boot 4.0 / Spring Security 7 Notes for Tests

**Important testing conventions:**

1. **Jackson 3:** Uses group ID `tools.jackson` (not `com.fasterxml.jackson`). Import `tools.jackson.databind.ObjectMapper` in tests.

2. **`@WebMvcTest`:** Support moved to `spring-boot-webmvc-test` artifact. Ensure it's in your test dependencies.

3. **SecurityConfig must be `@Import`ed:** In `@WebMvcTest` tests, SecurityConfig is no longer auto-scanned. Add `@Import(SecurityConfig.class)` to your test class.

4. **JWT Testing:** Do not use `@WithMockUser` for JWT-protected endpoints.
   - Use `SecurityMockMvcRequestPostProcessors.jwt()` to attach an authenticated JWT
   - For endpoints that resolve `@AuthenticationPrincipal Jwt jwt`, configure claims on the `jwt()` post-processor

5. **JwtDecoder Bean:** If a test needs JWT decoding to succeed, provide or mock a `JwtDecoder` bean in the test context. If it only needs an authenticated request, prefer `jwt()` and skip token parsing.

6. **Timestamps:** All entity timestamps use `java.time.Instant` (mapped to PostgreSQL `TIMESTAMPTZ`). Do not use `LocalDateTime` for any new timestamp fields.

7. **OAuth2 Storage:** Spring Authorization Server persists tokens in the `oauth2_authorization` table (Flyway V3). Do not reference the old `refresh_tokens` table in new code or tests.

---

## Developer Reminders

### Code Style & Quality

- **No drive-by refactors:** Keep diffs minimal — no style-only changes mixed with functional changes
- **English only:** All comments, commit messages, and documentation must be in English
- **Tests required:** New features require unit tests; database-touching features require integration tests

### Security Patterns

- **Never log sensitive data:** Passwords, tokens, secrets
- **Use parameterized queries:** Prevent SQL injection (Spring Data JPA does this by default)
- **Validate input:** Use `@Valid` and Jakarta Validation annotations on DTOs
- **Password hashing:** Always use `passwordEncoder.encode()` — never store plaintext

### Database Conventions

- **Migrations:** All schema changes **must** go through Flyway
- **Naming:** New migrations follow `V{n}__{description}.sql` (two underscores)
- **Never edit existing migrations:** Flyway checksums will fail on next startup
- **Flyway history table:** Named `flyway_schema_history_auth` to avoid conflicts when multiple services share the same PostgreSQL instance

**Current migrations:**

| Version | Description |
|---------|-------------|
| V1 | Initial schema: `users` + `refresh_tokens` tables |
| V2 | Widens `password_hash` to VARCHAR(255), resizes `refresh_tokens.token` to VARCHAR(64) for SHA-256 hashes, converts all timestamps to TIMESTAMPTZ |
| V3 | Creates `oauth2_authorization` and `oauth2_authorization_consent` tables for Spring Authorization Server token storage |
| V4 | Drops legacy `refresh_tokens` table |

**Next migration:** Use `V5__description.sql` for new changes.

### Entity Conventions

- **Timestamps:** Use `Instant` (not `LocalDateTime`) for all timestamp fields
- **Name patterns:** Entity class name matches table name (e.g., `User` -> `users`)
- **Columns:** Use snake_case for column names (e.g., `created_at`, `password_hash`)
- **Generated values:** Use `GenerationType.IDENTITY` for IDs

### API Conventions

- **RESTful:** Follow REST conventions (HTTP methods, status codes)
- **Versioning:** All API endpoints are prefixed with `/api/v1/`
- **DTOs:** Use separate DTO classes for request/response (don't expose entities directly)
- **Validation:** Annotate DTO fields with Jakarta Validation annotations
- **Error handling:** Use `GlobalExceptionHandler` for consistent error responses

### Configuration Conventions

- **Environment variables:** Prefix with service name for clarity (e.g., `DB_USERNAME`, not just `USERNAME`)
- **Property naming:** Use kebab-case in `application.yaml` (e.g., `access-token-expiry`)

---

## Useful Commands

### Build & Package

```bash
# Build the project
./mvnw clean package

# Skip tests
./mvnw clean package -DskipTests

# Build Docker image locally
./mvnw spring-boot:build-image
```

### Code Quality

```bash
# Code formatting (if IDE not configured)
# Note: Project doesn't have explicit formatter config yet

# Check for TODO comments
grep -r "TODO\|FIXME" src/ --include="*.java" --color

# Find unused imports (IDEA inspection)
# Run via IDE: Analyze > Run Inspection by Name > Unused import
```

### Dependencies

```bash
# List all dependencies
./mvnw dependency:tree

# Check for vulnerable dependencies
./mvnw org.owasp:dependency-check-maven:check

# Find specific dependency
./mvnw dependency:tree | grep -i spring
```

### Database

```bash
# Connect to local PostgreSQL (after port-forwarding)
PGPASSWORD=homelab psql -h localhost -U homelab -d homelabdb

# List tables
\dt

# View a table
\d users

# Query Flyway history
SELECT version, description, success FROM flyway_schema_history_auth ORDER BY installed_rank;

# Count users
SELECT COUNT(*) FROM users;
```

### Git Operations

```bash
# View commit history
 git log --oneline -20

# View changes
 git diff

# View staged changes
 git diff --staged

# Create a feature branch
git checkout -b feature/my-feature

# Rebase onto main
git fetch origin
git rebase origin/main

# Resolve merge conflicts (after rebase)
git status  # Find conflicted files
# Edit files, then:
git add <file>
git rebase --continue

# Amend a commit
git add .
git commit --amend

# Interactive rebase (squash commits)
git rebase -i HEAD~5
```

### Kubernetes Operations

```bash
# View auth-service pods
kubectl get pods -n apps -l app=auth-service

# View logs
kubectl logs -n apps deployment/auth-service --tail=50 -f

# View previous logs (if pod crashed)
kubectl logs -n apps deployment/auth-service --previous

# Port-forward to local
kubectl port-forward -n apps svc/auth-service 8080:8080

# Exec into pod
kubectl exec -n apps deploy/auth-service -it -- /bin/sh

# Describe pod (for troubleshooting)
kubectl describe pod -n apps <pod-name>

# View deployments
kubectl get deployment -n apps auth-service

# View rollout status
kubectl rollout status deployment/auth-service -n apps

# Restart deployment
git rollout restart deployment/auth-service -n apps
```

### Testing OIDC Flow Locally

```bash
# Start the service with env vars (see Local Development Setup above)
./mvnw spring-boot:run

# 1. Open login page in browser
# http://localhost:8080/login

# 2. Log in with a user that exists in the cluster database
# On success, you'll be at the Spring Authorization Server login page
# (This redirects from /login to the OIDC flow)

# 3. Test discovery document
curl -s http://localhost:8080/.well-known/openid-configuration | jq

# 4. Test JWKS endpoint
curl -s http://localhost:8080/oauth2/jwks | jq

# 5. To test token endpoint (requires a valid authorization code):
# Use a tool like Postman or curl with the code from the OIDC flow
```

### Bootstrap First Admin User

After first deploy (or when setting up a fresh local database), insert the initial admin:

```bash
# Generate BCrypt hash for password
HASH=$(htpasswd -bnBC 12 "" yourpassword | tr -d ':\n')

# Insert into database
 echo "INSERT INTO users (username, email, password_hash, role, status) VALUES ('admin', 'admin@homelab.local', '${HASH}', 'ADMIN', 'ACTIVE');" | \
  PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USERNAME -d homelabdb
```

---

## Code Review Checklist

Before merging a PR, verify:

- [ ] All tests pass (`./mvnw verify`)
- [ ] No drive-by refactors or style-only changes
- [ ] All comments and documentation are in English
- [ ] New features have unit tests
- [ ] Database-touching changes have integration tests
- [ ] Database migrations follow Flyway conventions
- [ ] No sensitive data committed (check `.gitignore`)
- [ ] environment variable names are consistent
- [ ] Error handling is appropriate
- [ ] Logging doesn't expose sensitive data
- [ ] API changes are documented in OpenAPI spec

---

## Troubleshooting Development Issues

### Common Problems & Solutions

**Problem:** Tests fail with `NoSuchBeanDefinitionException: SecurityConfig`

**Solution:** Add `@Import(SecurityConfig.class)` to your `@WebMvcTest` test class. In Spring Boot 4.0, SecurityConfig is no longer auto-scanned by the web slice.

---

**Problem:** `@WithMockUser` doesn't work for JWT-protected endpoints

**Solution:** Use `SecurityMockMvcRequestPostProcessors.jwt()` instead. For endpoints that resolve `@AuthenticationPrincipal Jwt jwt`, configure claims on the `jwt()` post-processor.

---

**Problem:** Integration tests fail with connection refused to PostgreSQL

**Solution:** Ensure Docker is running and the PostgreSQL container can start. Check with:
```bash
docker ps
```
If the container fails to start, try:
```bash
# Clean up any existing containers
docker system prune -f
# Then retry the tests
./mvnw verify
```

---

**Problem:** OIDC client authentication fails with "Invalid client credentials"

**Solution:** Ensure your client secret env var includes the `{noop}` prefix (for local dev) or `{bcrypt}` prefix (for hashed secrets). Without the prefix, Spring Security treats the stored value as BCrypt and validation will fail.

---

**Problem:** "Found non-empty schema but no history table" on startup

**Solution:** If the database already has tables but no Flyway history, set these env vars for the first rollout only:
```bash
export FLYWAY_BASELINE_ON_MIGRATE=true
export FLYWAY_BASELINE_VERSION=4  # Current highest migration
```
After the pod starts successfully, remove these env vars.

---

**Problem:** Flyway checksum mismatch

**Solution:** Restore the original migration file. Flyway calculates checksums for all V*.sql files and will fail if any existing migration was edited.

---

**Problem:** "No OIDC clients configured" on startup

**Solution:** Ensure `app.oidc.clients` is configured in `application.yaml` with at least one client. Check that all required env vars for client secrets are set.

---

## File Reference

### Key Files to Understand

| File | Purpose |
|------|---------|
| `AuthServiceApplication.java` | Main entry point, `@EnableScheduling` |
| `application.yaml` | All configuration including OIDC clients |
| `SecurityConfig.java` | Security filter chains, password encoder |
| `AuthorizationServerConfig.java` | OIDC server configuration |
| `UserService.java` | Business logic for user management |
| `UserController.java` | REST API endpoints |
| `User.java` | JPA entity for users |
| `TokenCleanupScheduler.java` | Automatic token cleanup job |
| `pom.xml` | Dependencies, build configuration |

### Files NOT to Edit Without Discussion

| File | Reason |
|------|--------|
| `k8s/deployment.yaml` | Managed by Flux CD (image tag) |
| GitHub Actions workflows | CI/CD pipeline |
| `.gitignore` | Version control exclusions |

---

## Continuous Integration

The project uses GitHub Actions for CI/CD:

- **Workflow:** `.github/workflows/build.yml`
- **Trigger:** Every push and PR to `main`
- **Test Job:** Runs `./mvnw verify` (unit + integration tests)
- **Build Job:** Multi-arch Docker image (`linux/amd64` + `linux/arm64`) pushed to `ghcr.io/doemefu/homelab-auth-service`

**Tags Pushed:**
- `${git-sha}` — Content-addressable, retained for debugging
- `main-YYYYMMDDTHHmmss` — Timestamp tag used by Flux CD for automatic deployment

**Note:** The `latest` tag is not pushed. Flux CD selects the newest `main-*` tag via `ImagePolicy`.

---

## Environment Variable Reference

### Required for Local Development

| Variable | Purpose | Example |
|----------|---------|---------|
| `DB_USERNAME` | PostgreSQL username | `homelab` |
| `DB_PASSWORD` | PostgreSQL password | `homelab` |
| `GRAFANA_CLIENT_SECRET` | Grafana OIDC client secret | `{noop}secret` |
| `HA_CLIENT_SECRET` | Home Assistant OIDC client secret | `{noop}secret` |
| `DEVICE_SERVICE_CLIENT_SECRET` | device-service OIDC client secret | `{noop}secret` |
| `N8N_CLIENT_SECRET` | n8n OIDC client secret | `{noop}secret` |
| `LITELLM_CLIENT_SECRET` | LiteLLM OIDC client secret | `{noop}secret` |

### Optional

| Variable | Purpose | Default |
|----------|---------|---------|
| `DB_URL` | PostgreSQL JDBC URL | `jdbc:postgresql://localhost:5432/homelabdb` |
| `APP_JWT_PRIVATE_KEY` | Path to private key | `classpath:keys/private.pem` |
| `APP_JWT_PUBLIC_KEY` | Path to public key | `classpath:keys/public.pem` |
| `SENTRY_DSN` | Sentry DSN | (disabled if not set) |
| `FLYWAY_BASELINE_ON_MIGRATE` | Flyway baseline mode | `false` |
| `FLYWAY_BASELINE_VERSION` | Flyway baseline version | `4` |

---

## Final Notes

- **Ask for help:** If stuck, ask questions in the PR or discussion
- **Check existing code:** Follow patterns already established in the codebase
- **Keep it simple:** Prefer minimal, focused changes
- **Test thoroughly:** Ensure all existing tests still pass before pushing
- **Document changes:** Update relevant docs (including this file) when adding new patterns or conventions
