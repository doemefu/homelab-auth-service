# homelab-auth-service — Overview

**OIDC Identity Provider (Spring Authorization Server)** for the furchert.ch homelab IoT ecosystem.

---

## Context & Purpose

The `homelab-auth-service` is the **central authentication and authorization service** for the doemefu homelab environment. It provides:

- **Single Sign-On (SSO)** across all homelab services via OIDC Authorization Code Flow with PKCE
- **Token issuance and validation** for service-to-service communication
- **User management** through a REST API for administrative tasks

### Architecture Position

```
auth-service (this service)
├── OIDC SSO ├──> Grafana (https://grafana.furchert.ch)
├── OIDC SSO ├──> Home Assistant (https://ha.furchert.ch)
├── OIDC SSO ├──> n8n (https://n8n.furchert.ch)
├── OIDC SSO ├──> LiteLLM (https://ai.furchert.ch)
├── OIDC SSO ├──> device-service (https://device.furchert.ch)
└── JWKS endpoint ──> device-service (token validation)
                     └── JWKS endpoint ──> data-service (token validation)
```

**Key Design Principle:** Other services validate tokens by fetching the RSA public key from `/oauth2/jwks` at startup. There is **no runtime dependency** on auth-service for every request. This makes the architecture resilient — downstream services can continue validating tokens even if auth-service is temporarily unavailable.

---

## Features

### Core Capabilities

| Category | Feature | Description |
|----------|---------|-------------|
| **OIDC Provider** | OIDC Discovery | Endpoint at `/.well-known/openid-configuration` |
| | Authorization Code Flow | With PKCE support for web/mobile clients |
| | Refresh Tokens | Issued alongside access tokens |
| | UserInfo Endpoint | Returns standard OIDC claims + custom `role` claim |
| | JWT Tokens | Signed with RSA-2048 keys |
| | JWKS Endpoint | Public key rotation support via `/oauth2/jwks` |
| | RP-Initiated Logout | Endpoint at `/connect/logout` |
| **User Management** | CRUD API | Create, read, update, delete users |
| | Role-Based Access | Roles: `USER`, `ADMIN` |
| | Self-Service | Users can view own profile, reset own password |
| | Password Reset | Admin can reset any user, users can reset own with current password |
| | Status Management | Users can be `ACTIVE` or `INACTIVE` |
| **Administration** | Admin API | Full user CRUD with role elevation |
| | Token Cleanup | Automatic purge of expired OAuth2 authorizations (hourly) |
| | Health Checks | `/actuator/health` for liveness/readiness |
| | OpenAPI Docs | Swagger UI at `/swagger-ui.html` |

### Security Features

- **Password Hashing:** BCrypt with automatic encoding detection
- **Token Security:** RSA-2048 signed JWTs with configurable expiry
- **OIDC Client Secrets:** Supports `{noop}` (plaintext) and `{bcrypt}` (hashed) prefixes
- **Session Management:** Stateful sessions for OIDC flow, stateless JWT for API
- **CSRF Protection:** Enabled for form-based login, disabled for API endpoints

---

## Accessible URLs & APIs

### Base URL

- **Production:** `https://auth.furchert.ch`
- **Cluster-internal:** `http://auth-service.apps.svc.cluster.local:8080`

### OIDC Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/openid-configuration` | None | OIDC Discovery document |
| GET | `/oauth2/authorize` | Session (form login) | Authorization endpoint — initiates OIDC flow |
| POST | `/oauth2/token` | Client credentials (Basic) | Token endpoint — exchanges code for tokens |
| GET | `/oauth2/jwks` | None | JSON Web Key Set — public keys for token validation |
| GET | `/userinfo` | Bearer token | OIDC UserInfo endpoint — returns user claims |
| POST | `/connect/logout` | Session | RP-Initiated Logout — redirects to post-logout URL |
| GET | `/login` | None | Login page — form-based authentication |

### User CRUD API (v1)

**Base Path:** `/api/v1/users`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/users` | ADMIN | Create a new user |
| GET | `/api/v1/users/{id}` | Bearer token (ADMIN or self) | Get user details |
| PUT | `/api/v1/users/{id}` | ADMIN | Update user (username, email, role, status) |
| DELETE | `/api/v1/users/{id}` | ADMIN | Delete user |
| POST | `/api/v1/users/{id}/reset-password` | ADMIN or self | Reset password (self requires current password) |

### Management & Documentation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/actuator/health` | None | Health check — K8s liveness/readiness |
| GET | `/actuator/info` | None | Service metadata |
| GET | `/swagger-ui.html` | Session (form login) | Swagger UI — interactive API documentation |
| GET | `/api-docs` | Session (form login) | OpenAPI JSON specification |

---

## Technology Stack

| Component | Version/Technology |
|-----------|-------------------|
| **Runtime** | Java 25 (Temurin) |
| **Framework** | Spring Boot 4.0.5 |
| **Security** | Spring Security 7, Spring Authorization Server |
| **OIDC** | OpenID Connect 1.0 |
| **JWT** | RSA-2048 signed tokens |
| **Database** | PostgreSQL (Flyway migrations) |
| **ORM** | Spring Data JPA (Hibernate) |
| **API Docs** | SpringDoc OpenAPI 3.0.2 |
| **Templating** | Thymeleaf (login page) |
| **Error Tracking** | Sentry (optional) |
| **Container** | Multi-arch Docker (linux/amd64 + linux/arm64) |

---

## Service Contracts

### Token Claims

Standard OIDC claims plus custom claims:

```json
{
  "sub": "username",
  "name": "username",
  "email": "user@example.com",
  "role": "ADMIN",
  "iss": "https://auth.furchert.ch",
  "aud": "client-id",
  "iat": 1714234567,
  "exp": 1714235467
}
```

### Token Expiry

- **Access Token:** 15 minutes (configurable via `app.jwt.access-token-expiry`)
- **Refresh Token:** 7 days (configurable via `app.jwt.refresh-token-expiry`)
- **Authorization Code:** 5 minutes (hardcoded)

### Client Configuration

All OIDC clients are configured in `application.yaml` under `app.oidc.clients`. Each client requires:

- `client-id`: Unique identifier
- `client-secret`: Spring Security encoded ({noop} or {bcrypt} prefix)
- `redirect-uris`: List of allowed callback URLs
- `post-logout-redirect-uris`: Where to redirect after logout
- `scopes`: List of OIDC scopes (typically `openid`, `profile`, `email`)

See [INTERFACES.md](./INTERFACES.md) for client integration details.

---

## Related Repositories

| Repository | Purpose |
|------------|---------|
| [doemefu/homelab](https://github.com/doemefu/homelab) | Infrastructure-as-Code — Ansible, K3s cluster, platform services (PostgreSQL, InfluxDB, Mosquitto) |
| [doemefu/homelab-device-service](https://github.com/doemefu/homelab-device-service) | Real-time IoT device management — MQTT subscriber, InfluxDB writer, WebSocket broadcast, scheduling |
| [doemefu/homelab-data-service](https://github.com/doemefu/homelab-data-service) | Historical data queries (InfluxDB) + schedule CRUD |

Full architecture documentation: [homelab/docs/](https://github.com/doemefu/homelab/tree/main/docs)
