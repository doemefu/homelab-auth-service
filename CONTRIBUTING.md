# CONTRIBUTING.md — homelab-auth-service

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
│   │   ├── UserController.java
│   │   └── LoginController.java
│   │
│   ├── dto/                 # Data transfer objects
│   │   ├── CreateUserRequest.java
│   │   ├── UpdateUserRequest.java
│   │   ├── ResetPasswordRequest.java
│   │   └── UserResponse.java
│   │
│   ├── entity/              # JPA entities
│   │   ├── User.java
│   │   └── Role.java
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
│   └── AuthServiceApplication.java
│
├── src/main/resources/
│   ├── application.yaml
│   ├── db/migration/       # Flyway migrations V1-V5
│   └── templates/         # Thymeleaf templates
│
├── src/test/              # Tests (unit, controller, integration)
├── k8s/                  # Kubernetes manifests
├── .github/workflows/    # GitHub Actions CI/CD
└── pom.xml
```

---

## Local Development Setup

### 1. Clone and Initialize

```bash
git clone git@github.com:doemefu/homelab-auth-service.git
cd homelab-auth-service
```

### 2. Generate RSA Keys

```bash
mkdir -p src/main/resources/keys
openssl genrsa -out src/main/resources/keys/private.pem 2048
openssl rsa -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem

mkdir -p src/test/resources/keys
openssl genrsa -out src/test/resources/keys/private.pem 2048
openssl rsa -in src/test/resources/keys/private.pem -pubout -out src/test/resources/keys/public.pem
```

**IMPORTANT:** Do not commit runtime keys from `src/main/resources/keys/`; that directory is ignored by `.gitignore`. Test RSA keys under `src/test/resources/keys/*.pem` are tracked for tests, so only change them intentionally if the test fixtures need to be updated.

### 3. Port-Forward PostgreSQL

```bash
kubectl port-forward -n apps svc/postgresql 5432:5432
```

### 4. Set Environment Variables

```bash
export DB_USERNAME=homelab
export DB_PASSWORD=homelab
export GRAFANA_CLIENT_SECRET="{noop}local-dev-secret"
export HA_CLIENT_SECRET="{noop}local-dev-secret"
export DEVICE_SERVICE_CLIENT_SECRET="{noop}local-dev-secret"
export N8N_CLIENT_SECRET="{noop}local-dev-secret"
export LITELLM_CLIENT_SECRET="{noop}local-dev-secret"
```

**IMPORTANT:** The `{noop}` prefix is required for Spring Security's `DelegatingPasswordEncoder`.

### 5. Run the Service

```bash
./mvnw spring-boot:run
```

### 6. Verify

```bash
curl -s http://localhost:8080/actuator/health
curl -s http://localhost:8080/.well-known/openid-configuration | jq
curl -s http://localhost:8080/oauth2/jwks | jq
```

---

## Running Tests

```bash
# Unit tests only
./mvnw test

# Full suite including integration tests (requires Docker)
./mvnw verify

# Specific test
./mvnw test -Dtest=UserServiceTest
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
## Spring Boot 4.0 / Spring Security 7 Notes

1. **Jackson 3:** Use `tools.jackson` group ID
2. **@WebMvcTest:** Import `spring-boot-webmvc-test` artifact
3. **SecurityConfig:** Must be `@Import`ed in `@WebMvcTest` tests
4. **JWT Testing:** Use `SecurityMockMvcRequestPostProcessors.jwt()` instead of `@WithMockUser`
5. **Timestamps:** Use `java.time.Instant` (not `LocalDateTime`)
6. **OAuth2 Storage:** Uses `oauth2_authorization` table (Flyway V3)

---

## Developer Reminders

- **No drive-by refactors** — Keep diffs minimal
- **English only** — All comments and documentation
- **Tests required** — Unit tests for new features, integration tests for database changes
- **Never log secrets** — Passwords, tokens, sensitive data
- **Flyway migrations** — All schema changes must go through Flyway, never edit existing V*.sql files

---

## Useful Commands

### Git

```bash
git log --oneline -20
git diff
git checkout -b feature/my-feature
git rebase origin/main
```

### Kubernetes

```bash
kubectl get pods -n apps -l app=auth-service
kubectl logs -n apps deployment/auth-service --tail=50 -f
kubectl rollout status deployment/auth-service -n apps
kubectl rollout restart deployment/auth-service -n apps
kubectl exec -n apps deploy/auth-service -it -- /bin/sh
```

### Database

```bash
kubectl exec -n apps deploy/postgresql -- psql -U postgres -d homelabdb
SELECT * FROM flyway_schema_history_auth ORDER BY installed_rank;
```

---

## Code Review Checklist

- [ ] All tests pass (`./mvnw verify`)
- [ ] No drive-by refactors or style-only changes
- [ ] All comments in English
- [ ] New features have unit tests
- [ ] Database changes have integration tests
- [ ] No sensitive data committed

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Tests fail with `NoSuchBeanDefinitionException: SecurityConfig` | Add `@Import(SecurityConfig.class)` to test |
| `@WithMockUser` doesn't work for JWT endpoints | Use `SecurityMockMvcRequestPostProcessors.jwt()` |
| Integration tests fail with connection refused | Ensure Docker is running, `docker system prune -f` then retry |
| OIDC client auth fails with "Invalid client credentials" | Ensure secret has `{noop}` or `{bcrypt}` prefix |
| "Found non-empty schema but no history table" | Use `FLYWAY_BASELINE_ON_MIGRATE=true` and `FLYWAY_BASELINE_VERSION=4` |
| Flyway checksum mismatch | Restore original migration file |

---

## See Also

For more detailed development information, see **[DEVELOPMENT.md](./DEVELOPMENT.md)**.
