# homelab-auth-service

JWT authentication service for the doemefu homelab IoT ecosystem. 

**Port:** 8080 | **Package:** `ch.furchert.homelab.auth` | **Database:** PostgreSQL

---

## Responsibilities

- User CRUD (create, read, update, delete, password reset)
- JWT issuance and refresh (jjwt + RSA key pair, `kid: auth-service-v1`)
- JWKS endpoint for downstream services to validate tokens locally
- Role-based access control: `USER`, `ADMIN`
- Refresh tokens are SHA-256 hashed before database storage
- Username change or password reset invalidates all refresh tokens for the user
- Automatic purge of expired refresh tokens (hourly scheduled task)

**Does NOT:** talk to MQTT, InfluxDB, or any other service at runtime. Fully self-contained.

---

## API Reference

All endpoints are prefixed `/api/v1`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/login` | None | Returns `accessToken` + `refreshToken` |
| POST | `/api/v1/auth/refresh` | None (body: `refreshToken`) | Rotates refresh token, returns new pair |
| POST | `/api/v1/auth/logout` | Bearer JWT | Invalidates all refresh tokens for caller |
| GET | `/api/v1/auth/jwks` | None | RSA public key in JWK Set format (`kid: auth-service-v1`) |
| POST | `/api/v1/users` | ADMIN | Create user |
| GET | `/api/v1/users/{id}` | JWT (ADMIN or own ID) | Get user |
| PUT | `/api/v1/users/{id}` | ADMIN | Update user |
| DELETE | `/api/v1/users/{id}` | ADMIN | Delete user |
| POST | `/api/v1/users/{id}/reset-password` | ADMIN or self | Reset password (self requires `currentPassword`) |
| GET | `/actuator/health` | None | K8s liveness/readiness |
| GET | `/actuator/info` | None | Service info |
| GET | `/api-docs` | None | OpenAPI JSON spec |
| GET | `/swagger-ui.html` | None | Swagger UI |

---

## Local Development

### Prerequisites

- Java 25
- Docker (for integration tests)
- kubectl access to the K3s cluster

### 1. Generate RSA keys (one-time)

```bash
mkdir -p src/main/resources/keys
openssl genrsa -out src/main/resources/keys/private.pem 2048
openssl rsa -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem

mkdir -p src/test/resources/keys
openssl genrsa -out src/test/resources/keys/private.pem 2048
openssl rsa -in src/test/resources/keys/private.pem -pubout -out src/test/resources/keys/public.pem
```

> **Never commit these files.** `src/main/resources/keys/` is in `.gitignore`. For cluster deployment, inject production keys via the `homelab-auth-rsa-keys` K8s Secret (see [K8s Deployment](#k8s-deployment)).

### 2. Port-forward PostgreSQL

```bash
kubectl port-forward -n apps svc/postgres 5432:5432
```

### 3. Run

```bash
export DB_USERNAME=homelab
export DB_PASSWORD=homelab
./mvnw spring-boot:run
```

> The service connects to database `homelabdb` on `localhost:5432` (default in `application.yaml`). Ensure this database exists on the cluster PostgreSQL instance.

### 4. Tests

```bash
./mvnw test          # Unit tests only (no Docker needed)
./mvnw verify        # Full suite including integration tests (Docker required)
```

---

## Configuration

| Property | Env override | Default |
|----------|-------------|---------|
| `spring.datasource.username` | `DB_USERNAME` | — (required) |
| `spring.datasource.password` | `DB_PASSWORD` | — (required) |
| `app.jwt.private-key` | `APP_JWT_PRIVATE_KEY` | `classpath:keys/private.pem` |
| `app.jwt.public-key` | `APP_JWT_PUBLIC_KEY` | `classpath:keys/public.pem` |
| `app.jwt.access-token-expiry` | — | `900000` ms (15 min) |
| `app.jwt.refresh-token-expiry` | — | `604800000` ms (7 days) |

Expired refresh tokens are automatically purged every hour by `TokenCleanupScheduler`. No additional configuration required.

---

## Bootstrap — First Admin User

After first deploy, insert the initial admin via `psql`:

```sql
-- Generate hash: htpasswd -bnBC 12 "" yourpassword | tr -d ':\n'
INSERT INTO users (username, email, password_hash, role, status)
VALUES ('admin', 'admin@homelab.local', '$2a$12$<bcrypt-hash>', 'ADMIN', 'ACTIVE');
```

---

## Architecture

This service is 1 of 3 microservices in the homelab IoT stack.

```
auth-service   ──JWKS──>  device-service
                    └──>  data-service
```

Other services validate JWTs by fetching the RSA public key from `/api/v1/auth/jwks` at startup — no runtime dependency on auth-service for every request.

**Key design:** jjwt + RSA (not Spring Authorization Server). Simple, self-contained, auditable.

---

## K8s Deployment

Manifests are in `k8s/`:
- `k8s/deployment.yaml` — Deployment in namespace `apps`, image tag `:<git-sha>` (replace before `kubectl apply`), mounts RSA keys from Secret `homelab-auth-rsa-keys`, reads DB credentials from Secret `homelab-db-credentials`
- `k8s/service.yaml` — ClusterIP Service on port 8080

Required Secrets (must exist in namespace `apps` before first deploy):

```bash
# Database credentials
kubectl create secret generic homelab-db-credentials -n apps \
  --from-literal=username=<db-user> \
  --from-literal=password=<db-pass>

# RSA key pair
kubectl create secret generic homelab-auth-rsa-keys -n apps \
  --from-file=private.pem=<path-to-private.pem> \
  --from-file=public.pem=<path-to-public.pem>
```

---

## CI/CD

GitHub Actions workflow at `.github/workflows/build.yml`:

- **test** job: runs `./mvnw verify` on every push and PR to `main` (Testcontainers integration tests run on the CI runner)
- **build-and-push** job: builds a multi-arch image (`linux/amd64` + `linux/arm64`) and pushes to `ghcr.io/doemefu/homelab-auth-service:<git-sha>` — runs only on push to `main` after tests pass

Image registry: `ghcr.io/doemefu/homelab-auth-service`


