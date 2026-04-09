# homelab-auth-service

JWT authentication service for the doemefu homelab IoT ecosystem. 

**Port:** 8080 | **Package:** `ch.furchert.homelab.auth` | **Database:** PostgreSQL

---

## Responsibilities

- OIDC Identity Provider (Spring Authorization Server) for SSO across furchert.ch homelab services
- OIDC Discovery at `/.well-known/openid-configuration`
- Authorization Code Flow with PKCE for Grafana, Home Assistant, and other clients
- JWKS endpoint (`/oauth2/jwks`) for downstream services to validate tokens
- User CRUD (create, read, update, delete, password reset) via admin API
- Role-based access control: `USER`, `ADMIN`
- Automatic purge of expired OAuth2 authorizations (hourly)

**Does NOT:** talk to MQTT, InfluxDB, or any other service at runtime. Fully self-contained.

---

## API Reference

### OIDC Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/openid-configuration` | None | OIDC Discovery document |
| GET | `/oauth2/authorize` | Session (form login) | Authorization endpoint |
| POST | `/oauth2/token` | Client credentials (Basic) | Token endpoint |
| GET | `/oauth2/jwks` | None | JSON Web Key Set |
| GET | `/userinfo` | Bearer token | OIDC UserInfo endpoint |
| POST | `/connect/logout` | Session | RP-Initiated Logout |
| GET | `/login` | None | Login page |

### User CRUD API

All user endpoints are prefixed `/api/v1`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/users` | ADMIN | Create user |
| GET | `/api/v1/users/{id}` | Bearer token (ADMIN or own ID) | Get user |
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
| `app.oidc.issuer` | — | — (required; must match the public ingress URL exactly) |
| `app.oidc.clients[0].client-secret` | `GRAFANA_CLIENT_SECRET` | — (required; must include `{id}` prefix, e.g. `{noop}secret`) |
| `app.oidc.clients[1].client-secret` | `HA_CLIENT_SECRET` | — (required; must include `{id}` prefix, e.g. `{noop}secret`) |

Expired OAuth2 authorizations are automatically purged every hour by `TokenCleanupScheduler`. No additional configuration required.

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
auth-service   ──OIDC SSO──>  Grafana
                    └──>  Home Assistant
                    └──JWKS──>  device-service
                    └──JWKS──>  data-service
```

Other services validate tokens by fetching the RSA public key from `/oauth2/jwks` at startup — no runtime dependency on auth-service for every request. SSO is provided via OIDC Authorization Code Flow with PKCE.

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

---

## Related Repositories

| Repo | Description |
|------|-------------|
| [homelab](https://github.com/doemefu/homelab) | Infrastructure-as-Code — Ansible, K3s cluster, platform services (PostgreSQL, InfluxDB, Mosquitto) |
| [homelab-device-service](https://github.com/doemefu/homelab-device-service) | Real-time IoT device management — MQTT subscriber, InfluxDB writer, WebSocket broadcast, scheduling |
| homelab-data-service | Historical data queries (InfluxDB) + schedule CRUD (not yet created) |

Full architecture docs (migration plan, current/target architecture, cross-service contracts): [homelab/docs/](https://github.com/doemefu/homelab/tree/main/docs)
