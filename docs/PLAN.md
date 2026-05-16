# homelab-auth-service — Implementation Plan

## Scope

**Green-field deployment. No data migration from any prior system.**
- Flyway V1 creates the schema only — no seed data, no user imports
- First admin user is created manually via `psql` after first deploy (see Bootstrap below)
- This service has no runtime dependency on any other service

---

## Context

The auth-service is the **first service to build** (M1). It issues JWTs (jjwt + RSA), manages users, and exposes a JWKS endpoint so other services can validate tokens locally.

**Repo:** `github.com/doemefu/homelab-auth-service`
**Port:** 8080
**Database:** PostgreSQL — `users` + `refresh_tokens` tables
**Package:** `ch.furchert.homelab.auth`

---

## Pinned Versions

| Component | Version |
|-----------|---------|
| Java | 25 |
| Spring Boot | 4.0.5 |
| jjwt | 0.12.6 |
| Testcontainers BOM | 1.20.4 |
| springdoc-openapi | 2.7.0 (verify SB 4.0 compat before Step 17 — may need upgrade) |
| Base image | `eclipse-temurin:25-jre-alpine` |

---

## Spring Boot 4.0 Notes

- **Flyway:** `spring-boot-starter-flyway` — `flyway-database-postgresql` is NOT needed (remove from pom.xml)
- **Jackson 3:** Group ID is `tools.jackson`. `Jackson2ObjectMapperBuilderCustomizer` → `JsonMapperBuilderCustomizer`
- **Testing:** `@SpringBootTest` no longer auto-configures MockMvc — add `@AutoConfigureMockMvc` explicitly
- **Spring Security 7.0:** Review security filter chain API changes
- **Web starter:** `spring-boot-starter-webmvc` — correct for SB 4.0 servlet stack

---

## API Versioning

**Strategy: URL path prefix `/api/v1/`**

Rationale: explicit, discoverable, no request-header magic, works out-of-the-box with Spring `@RequestMapping`. All controllers use `@RequestMapping("/api/v1/...")`. Future breaking changes introduce a `/api/v2/` prefix.

## API Endpoints

All paths are prefixed with `/api/v1`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/login` | No | Authenticate, return JWT + refresh token |
| POST | `/api/v1/auth/refresh` | Refresh token (body) | Issue new access token |
| POST | `/api/v1/auth/logout` | JWT | Invalidate refresh token |
| GET | `/api/v1/auth/jwks` | No | RSA public key set for token validation |
| POST | `/api/v1/users` | ADMIN | Create user |
| GET | `/api/v1/users/{id}` | JWT — ADMIN or own user only | Get user by ID |
| PUT | `/api/v1/users/{id}` | ADMIN | Update user |
| DELETE | `/api/v1/users/{id}` | ADMIN | Delete user |
| POST | `/api/v1/users/{id}/reset-password` | ADMIN or self (current password required for self) | Reset password |

**Actuator** (no auth, outside versioned prefix):
- `GET /actuator/health` — K8s liveness/readiness probe
- `GET /actuator/info`

---

## Database Schema (Flyway V1 — schema only, no seed data)

```sql
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    email           VARCHAR(100) NOT NULL UNIQUE,
    password_hash   VARCHAR(72)  NOT NULL,
    role            VARCHAR(10)  NOT NULL DEFAULT 'USER',
    status          VARCHAR(10)  NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token       VARCHAR(2048) NOT NULL UNIQUE,
    expires_at  TIMESTAMP    NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token   ON refresh_tokens(token);
```

---

## Bootstrap — First Admin User

After first deploy, create the initial admin via `psql` directly:

```sql
-- Generate BCrypt hash first: htpasswd -bnBC 12 "" yourpassword | tr -d ':\n'
INSERT INTO users (username, email, password_hash, role, status)
VALUES ('admin', 'admin@homelab.local', '$2a$12$<your-bcrypt-hash>', 'ADMIN', 'ACTIVE');
```

One-time manual operator step — not in Flyway, not in application code.

---

## RSA Keys

### Setup (one-time, per environment)

```bash
# Local dev keys (gitignored)
mkdir -p src/main/resources/keys
openssl genrsa -out src/main/resources/keys/private.pem 2048
openssl rsa -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem

# Test keys (separate pair — never reuse dev/prod keys in tests)
mkdir -p src/test/resources/keys
openssl genrsa -out src/test/resources/keys/private.pem 2048
openssl rsa -in src/test/resources/keys/private.pem -pubout -out src/test/resources/keys/public.pem
```

### Production (K8s)
Keys mounted from K8s Secret. Override classpath defaults via env vars in the K8s deployment:
```yaml
env:
  - name: APP_JWT_PRIVATE_KEY
    value: "file:/etc/secrets/private.pem"
  - name: APP_JWT_PUBLIC_KEY
    value: "file:/etc/secrets/public.pem"
```

---

## Implementation Order

| Step | Component | Files |
|------|-----------|-------|
| 0 | **Fix pom.xml** — remove `flyway-database-postgresql`, move Testcontainers BOM to `<dependencyManagement>`, replace non-existent `spring-boot-starter-*-test` deps with `spring-boot-starter-test` | `pom.xml` |
| 1 | Flyway V1 migration | `src/main/resources/db/migration/V1__init.sql` |
| 2 | User entity + repository | `entity/User.java`, `repository/UserRepository.java` |
| 3 | RefreshToken entity + repo | `entity/RefreshToken.java`, `repository/RefreshTokenRepository.java` |
| 4 | RSA key config | `config/RsaKeyProperties.java`, `security/RsaKeyProvider.java` |
| 5 | JWT service | `security/JwtService.java` |
| 6 | UserDetailsService | `security/CustomUserDetailsService.java` |
| 7 | JWT auth filter | `security/JwtAuthenticationFilter.java` |
| 8 | Security config | `config/SecurityConfig.java` |
| 9 | DTOs + exception handler | `dto/*.java`, `exception/GlobalExceptionHandler.java` |
| 10 | AuthService + AuthController | `service/AuthService.java`, `controller/AuthController.java` |
| 11 | UserService + UserController | `service/UserService.java`, `controller/UserController.java` |
| 12 | Unit tests | `*Test.java` |
| 13 | Integration tests | `*IntegrationTest.java` |
| 14 | Dockerfile | `Dockerfile` |
| 15 | K8s manifests | `k8s/deployment.yaml`, `k8s/service.yaml` |
| 16 | GitHub Actions | `.github/workflows/build.yml` |
| 17 | README + docs | `README.md`, `CHANGELOG.md` |

---

## Key Architectural Decisions

### Step 0 — pom.xml fixes (exact changes)

**Remove:**
```xml
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-database-postgresql</artifactId>
</dependency>
```

**Remove all `spring-boot-starter-*-test` entries. Replace with:**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

**Move Testcontainers BOM out of `<dependencies>` into `<dependencyManagement>`:**
```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>testcontainers-bom</artifactId>
            <version>1.20.4</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### application.yaml — no fallback credentials
```yaml
spring:
  datasource:
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
```
No default values — startup fails explicitly if env vars are missing.

### SecurityConfig — endpoint rules
```
/api/v1/auth/login                    permitAll
/api/v1/auth/refresh                  permitAll
/api/v1/auth/jwks                     permitAll
/actuator/health                       permitAll
/actuator/info                         permitAll
POST   /api/v1/users                  hasRole('ADMIN')
GET    /api/v1/users/{id}             authenticated + (ADMIN or own ID — enforced in service)
PUT    /api/v1/users/{id}             hasRole('ADMIN')
DELETE /api/v1/users/{id}             hasRole('ADMIN')
POST   /api/v1/users/{id}/reset-password  authenticated (ADMIN or self — enforced in service)
everything else                        authenticated
```

### RSA Key Loading
`@ConfigurationProperties("app.jwt")` binds `private-key` and `public-key` to Spring `Resource`. `RsaKeyProvider` loads PEM at startup via `KeyFactory` (PKCS8 for private, X509 for public). Local dev: classpath. Prod: env var overrides to `file:` path.

### JWT Claims
`sub` (username), `role` (USER/ADMIN), `iat`, `exp`, `iss` (homelab-auth-service)

### JWKS Endpoint
`GET /auth/jwks` returns RSA public key in JWK format using jjwt's `Jwks.builder()` (0.12.x+). Compatible with NimbusJwtDecoder.

### Refresh Tokens
DB-backed (revocable). On refresh: delete old token, issue new (rotation). On logout: delete all tokens for user. Known risk: if response is lost in transit the client must re-authenticate — accepted for homelab simplicity.

### Roles
`VARCHAR` column — `USER` or `ADMIN`. No roles table.

### Flyway
`spring.flyway.table=flyway_schema_history_auth` — isolated from other services sharing the same DB.

---

## Configuration (application.yaml)

```yaml
spring:
  application:
    name: auth-service
  datasource:
    url: jdbc:postgresql://localhost:5432/homelabdb
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: validate
    open-in-view: false
  flyway:
    enabled: true
    table: flyway_schema_history_auth

server:
  port: 8080

app:
  jwt:
    private-key: classpath:keys/private.pem
    public-key: classpath:keys/public.pem
    access-token-expiry: 900000      # 15 min
    refresh-token-expiry: 604800000  # 7 days

management:
  endpoints:
    web:
      exposure:
        include: health,info

springdoc:
  api-docs:
    path: /api-docs
  swagger-ui:
    path: /swagger-ui.html
```

---

## Tests

### Unit Tests
| Test | Scope |
|------|-------|
| `UserServiceTest` | CRUD, password encoding, duplicate detection |
| `AuthServiceTest` | Login, token generation, refresh rotation, logout |
| `AuthControllerTest` | MockMvc + `@AutoConfigureMockMvc`: success, validation error, 401, 403, 404 |
| `UserControllerTest` | MockMvc + `@AutoConfigureMockMvc`: CRUD, role-based access, own-ID check |

### Integration Tests
| Test | Scope |
|------|-------|
| `AuthIntegrationTest` | Full flow: login → access protected endpoint → refresh → logout |
| `SecurityConfigTest` | 401 unauthenticated, 403 USER hitting ADMIN endpoint |

**Test isolation:** `@BeforeEach` truncates `refresh_tokens` and `users` tables (in that order, respecting FK). Testcontainers: `PostgreSQLContainer("postgres:17-alpine")` + `@DynamicPropertySource`.

---

## K8s Manifest Spec (Step 15)

Minimum required in `k8s/deployment.yaml`:
- Namespace: `apps`
- Image: `ghcr.io/doemefu/homelab-auth-service:<version>` — never `latest`
- Resources: `requests: {cpu: 100m, memory: 256Mi}` / `limits: {cpu: 500m, memory: 512Mi}`
- Liveness probe: `GET /actuator/health` — `initialDelaySeconds: 30, periodSeconds: 10`
- Readiness probe: `GET /actuator/health` — `initialDelaySeconds: 20, periodSeconds: 5`
- RSA keys: volumeMount from K8s Secret (`homelab-auth-rsa-keys`) at `/etc/secrets/`
- Env: `APP_JWT_PRIVATE_KEY=file:/etc/secrets/private.pem`, `APP_JWT_PUBLIC_KEY=file:/etc/secrets/public.pem`, `DB_USERNAME` + `DB_PASSWORD` from `secretKeyRef`

---

## GitHub Actions Spec (Step 16)

File: `.github/workflows/build.yml`
- Trigger: push to `main`, pull requests
- Steps: checkout → set up Java 25 → mvn verify → docker buildx → push to `ghcr.io/doemefu/homelab-auth-service`
- Platforms: `linux/amd64,linux/arm64` (QEMU + buildx)
- Image tag: git SHA for pushes to main; no push on PRs

---

## Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|------------|
| R1 | Spring Boot 4.0 API differences from 3.x | medium | high | Use context7 before each component |
| R2 | springdoc-openapi 2.7.0 incompatible with SB 4.0 | medium | medium | Verify version via context7 in Step 17; upgrade if needed |
| R3 | Refresh token response lost in transit | low | low | Accepted — homelab; user must re-authenticate |

---

## Validation

```bash
./mvnw verify

# After deploy:
kubectl port-forward -n apps svc/auth-service 8080:8080
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'
curl -s http://localhost:8080/auth/jwks
```
