# homelab-auth-service — Deployment & Operations

Comprehensive deployment and operational guidance for auth-service.

---

## Infrastructure requirements

- **Kubernetes:** K3s cluster, namespace `apps`
- **Nodes:** ARM64 (raspi5, raspi4) + future amd64 (mba1, mba2)
- **Multi-arch:** Docker image supports `linux/arm64` and `linux/amd64`
- **Ingress:** Cloudflare Tunnel via `platform` namespace
- **Database:** PostgreSQL `postgresql.apps.svc.cluster.local:5432`, database `homelabdb`

---

## Dependencies

### Kubernetes Secrets (required in `apps` namespace)

| Secret | Keys | Purpose |
|--------|------|---------|
| `homelab-db-credentials` | `username`, `password` | Database |
| `homelab-auth-rsa-keys` | `private.pem`, `public.pem` | JWT signing keys |
| `homelab-auth-secrets` | Client secrets for Grafana, Home Assistant, device-service, n8n, LiteLLM | OIDC client auth |
| `sentry-dsn` | `dsn` | Error tracking (optional) |

### Cloudflare Tunnel

Add to `infra/playbooks/40_platform.yml`:
```yaml
- hostname: auth.furchert.ch
  service: http://auth-service.apps.svc.cluster.local:8080
```
Apply: `ansible-playbook infra/playbooks/40_platform.yml`

---

## Deployment methods

### Flux CD (Production - Automated)

1. Push to `main` branch
2. GitHub Actions builds multi-arch Docker image
3. Flux CD detects new `main-YYYYMMDDTHHmmss` tag
4. Flux CD updates `k8s/deployment.yaml` and rolls out automatically

**Manual Flux operations:**
```bash
flux get kustomizations -n flux-system
flux reconcile kustomization auth-service -n flux-system --with-source
flux suspend image update auth-service -n flux-system  # emergency
flux resume image update auth-service -n flux-system
```

### Manual (Development Only)

```bash
kubectl apply -k k8s/
kubectl rollout status deployment/auth-service -n apps
```

---

## Step-by-step deployment

### First-time

1. **Create secrets:**
```bash
kubectl create secret generic homelab-db-credentials -n apps --from-literal=username=<user> --from-literal=password=<pass>
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
kubectl create secret generic homelab-auth-rsa-keys -n apps --from-file=private.pem --from-file=public.pem
kubectl create secret generic homelab-auth-secrets -n apps \
  --from-literal=grafana-client-secret="{noop}<secret>" \
  --from-literal=ha-client-secret="{noop}<secret>" \
  --from-literal=device-service-client-secret="{noop}<secret>" \
  --from-literal=n8n-client-secret-authservice="{noop}<secret>" \
  --from-literal=litellm-client-secret-authservice="{noop}<secret>"
rm private.pem public.pem
```

2. **Configure Cloudflare Tunnel** (see above)

3. **Bootstrap first admin:**
```bash
HASH=$(htpasswd -bnBC 12 "" yourpassword | tr -d ':\n')
kubectl exec -n apps deploy/postgresql -- psql -U postgres -d homelabdb \
  -c "INSERT INTO users (username, email, password_hash, role, status) VALUES ('admin', 'admin@homelab.local', '${HASH}', 'ADMIN', 'ACTIVE');"
```

4. **Deploy:** Push to `main` or `kubectl apply -k k8s/`

### Upgrade

Push to `main` — Flux CD handles everything automatically.

---

## Post-deployment verification

```bash
kubectl get pods -n apps -l app=auth-service
kubectl rollout status deployment/auth-service -n apps

# Verify health
kubectl port-forward -n apps svc/auth-service 8080:8080
curl -s http://localhost:8080/actuator/health

# Verify OIDC
curl -s https://auth.furchert.ch/.well-known/openid-configuration | jq
curl -s https://auth.furchert.ch/oauth2/jwks | jq
```

---

## Health checks & monitoring

- **Liveness Probe:** `GET /actuator/health` (30s initial, 10s period, 3 failures)
- **Readiness Probe:** `GET /actuator/health` (20s initial, 5s period, 3 failures)
- **Endpoints:** `/actuator/health`, `/actuator/info` (unauthenticated)

---

## Runbooks

### Restart service
```bash
kubectl rollout restart deployment/auth-service -n apps
kubectl rollout status deployment/auth-service -n apps
```

### RSA key rotation
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
kubectl delete secret homelab-auth-rsa-keys -n apps
kubectl create secret generic homelab-auth-rsa-keys -n apps --from-file=private.pem --from-file=public.pem
kubectl rollout restart deployment/auth-service -n apps
rm private.pem public.pem
```
**Note:** All existing tokens become invalid immediately.

### Add new OIDC client
1. Generate encoded secret: `{noop}<plaintext>` or `{bcrypt}$2a$...`
2. Update secret: `kubectl patch secret homelab-auth-secrets -n apps --type merge -p '{"stringData":{"new-client-secret":"{noop}<secret>"}}'`
3. Add client config to `application.yaml`
4. Add env var reference to `k8s/deployment.yaml`
5. Restart service

---

## Troubleshooting

### Service fails to start - Flyway
| Error | Solution |
|-------|----------|
| Database unreachable | Check `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` |
| Checksum mismatch | Restore original migration file |
| Non-empty schema, no history | Use `FLYWAY_BASELINE_ON_MIGRATE=true`, `FLYWAY_BASELINE_VERSION=4` for first deploy |

### Service fails to start - RSA keys
| Error | Solution |
|-------|----------|
| No such file/directory | Check volume mount `/etc/secrets` |
| Invalid PEM format | Regenerate keys and recreate secret |

### JWT validation failures
- Keys rotated? Restart downstream services
- Issuer mismatch? Ensure `app.oidc.issuer=https://auth.furchert.ch`
- Token expired? Client must refresh

### OIDC login issues
- Issuer mismatch? Set `app.oidc.issuer=https://auth.furchert.ch`
- Forward headers? Set `server.forward-headers-strategy=native`
- Multiple pods? Scale to 1 or add session backend

### Pod/Image issues
```bash
kubectl describe pod -n apps <pod-name>
```
Common: Insufficient CPU/memory, nodeSelector mismatch, image not available for architecture.

---

## Configuration reference

### Environment variables

| Variable | Source | Required | Description |
|----------|--------|----------|-------------|
| `DB_USERNAME` | `homelab-db-credentials` | Yes | PostgreSQL username |
| `DB_PASSWORD` | `homelab-db-credentials` | Yes | PostgreSQL password |
| `DB_URL` | Config | No | JDBC URL (default: `jdbc:postgresql://postgresql.apps.svc.cluster.local:5432/homelabdb`) |
| `GRAFANA_CLIENT_SECRET` | `homelab-auth-secrets` | Yes | Grafana OIDC client secret |
| `HA_CLIENT_SECRET` | `homelab-auth-secrets` | Yes | Home Assistant OIDC client secret |
| `DEVICE_SERVICE_CLIENT_SECRET` | `homelab-auth-secrets` | Yes | device-service OIDC client secret |
| `N8N_CLIENT_SECRET` | `homelab-auth-secrets` | Yes | n8n OIDC client secret |
| `LITELLM_CLIENT_SECRET` | `homelab-auth-secrets` | Yes | LiteLLM OIDC client secret |
| `SENTRY_DSN` | `sentry-dsn` | No | Sentry error tracking |

---

## Quick commands

```bash
# Status
kubectl get pods -n apps -l app=auth-service
kubectl rollout status deployment/auth-service -n apps

# Logs
kubectl logs -n apps deployment/auth-service --tail=100 -f

# Restart
kubectl rollout restart deployment/auth-service -n apps

# Flux
flux get kustomizations -n flux-system
flux reconcile kustomization auth-service -n flux-system --with-source
```
