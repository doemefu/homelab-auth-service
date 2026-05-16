# homelab-auth-service

**OIDC Identity Provider (Spring Authorization Server)** for the furchert.ch homelab IoT ecosystem.

---

## Documentation

This repository uses a structured documentation approach with four main guides at the repository root:

| Document | Purpose | When to Read |
|----------|---------|---------------|
| **[OVERVIEW.md](./OVERVIEW.md)** | What this repo is about, context, features, URLs, APIs | First — understand the service |
| **[INTERFACES.md](./INTERFACES.md)** | How other services interact with auth-service | When integrating a new client |
| **[DEPLOYMENT.md](./DEPLOYMENT.md)** | Deployment instructions, infrastructure, troubleshooting | When deploying to production |
| **[CONTRIBUTING.md](./CONTRIBUTING.md)** | Development instructions, useful commands, patterns | When developing locally |
| **[docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md)** | Extended development guide | For detailed development reference |

---

## Quick Start

### Local Development

```bash
# 1. Generate RSA keys
mkdir -p src/main/resources/keys
openssl genrsa -out src/main/resources/keys/private.pem 2048
openssl rsa -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem

# 2. Port-forward PostgreSQL
kubectl port-forward -n apps svc/postgresql 5432:5432

# 3. Set environment variables & run
export DB_USERNAME=homelab
export DB_PASSWORD=homelab
./mvnw spring-boot:run
```

### Deploy to Production

Push to `main` branch — **Flux CD handles everything automatically**.

---

## Quick Reference

| URL | Description |
|-----|-------------|
| `https://auth.furchert.ch/.well-known/openid-configuration` | OIDC Discovery |
| `https://auth.furchert.ch/oauth2/authorize` | Authorization Endpoint |
| `https://auth.furchert.ch/oauth2/token` | Token Endpoint |
| `https://auth.furchert.ch/oauth2/jwks` | JWKS (Public Keys) |
| `https://auth.furchert.ch/userinfo` | UserInfo Endpoint |
| `https://auth.furchert.ch/api/v1/users` | User CRUD API (Admin) |

---

## Architecture

```
auth-service (OIDC Identity Provider)
├── OIDC SSO ├──> Grafana
├── OIDC SSO ├──> Home Assistant
├── OIDC SSO ├──> n8n
├── OIDC SSO ├──> LiteLLM
├── OIDC SSO ├──> device-service
└── JWKS ──> device-service & data-service (token validation)
```

---

## Deprecated Documentation

Old documentation files have been renamed with `_old` suffix:
- `README_old.md`
- `CONTRIBUTING_old.md`
- `DEPLOYMENT_old.md`
- `OPERATIONS_old.md`

Their content has been migrated to the new documentation structure.

---

## Support

- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Status:** See [CHANGELOG.md](./CHANGELOG.md) for recent changes

---

## License

MIT License — See [LICENSE](./LICENSE)
