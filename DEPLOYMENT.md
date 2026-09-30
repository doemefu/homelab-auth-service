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
| `homelab-auth-secrets` | Client secrets for Grafana, Home Assistant, device-service, n8n, LiteLLM; optional `claude-mcp-hub-client-secret`, `claude-mcp-hub-allowed-users` | OIDC client auth |
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

   Optional keys in `homelab-auth-secrets` for the login-event outbox (NM-4, see `INTERFACES.md` §2 "data-service"):
   `data-service-client-secret` (`{noop}<secret>`) and `login-event-hmac-key` (at least 32 characters, e.g. `openssl rand -hex 32`).
   Both are wired with `optional: true`. Without them, auth-service starts normally and login-event capture stays off.
   In production these keys come from SOPS through playbook 59.

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

- **Startup Probe:** `GET /actuator/health` (5s period, 60 failures — 300s budget). JVM startup takes 65-95s at the 1 CPU limit on the fastest node (mba1) and can exceed 150s under contention on the 4-core node; the budget keeps roughly 2x margin over the worst observed case.
- **Liveness Probe:** `GET /actuator/health` (10s period, 3 failures)
- **Readiness Probe:** `GET /actuator/health` (5s period, 3 failures)
- **Endpoints:** `/actuator/health`, `/actuator/info` (unauthenticated)
- **Resources:** 1 CPU limit / 100m request, 512Mi memory limit / 256Mi request

---

## Runbooks

### Restart service
```bash
kubectl -n apps delete pod -l app=auth-service
kubectl -n apps get pods -l app=auth-service   # new pod: small AGE, then READY 1/1
```
Do not use `kubectl rollout restart`. Flux strips its `restartedAt` annotation on the next Kustomization apply, which can cancel the rollout before the new pod is Ready, while `rollout status` still reports success. Deleting the pod makes the ReplicaSet recreate it; with one replica, expect ~30–60 s of downtime. Verify with the pod age and the startup log, not with `rollout status` alone.

### RSA key rotation
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
kubectl delete secret homelab-auth-rsa-keys -n apps
kubectl create secret generic homelab-auth-rsa-keys -n apps --from-file=private.pem --from-file=public.pem
kubectl -n apps delete pod -l app=auth-service
rm private.pem public.pem
```
**Note:** All existing tokens become invalid immediately.

### Add new OIDC client
1. Generate encoded secret: `{noop}<plaintext>` or `{bcrypt}$2a$...`
2. Update secret: `kubectl patch secret homelab-auth-secrets -n apps --type merge -p '{"stringData":{"new-client-secret":"{noop}<secret>"}}'`
3. Add client config to `application.yaml`
4. Add env var reference to `k8s/deployment.yaml`
5. Restart service

### Enable or change the claude-mcp-hub client

Contract: `../docs/080-mcp-hub.md` §4.1 and §4.6; see `INTERFACES.md` §2 "claude-mcp-hub".
Every step is an owner action or needs the owner's go. All SQL runs inside the database
pod (no password, no local client).

1. The owner sets the SOPS variables `auth_service_claude_mcp_hub_client_secret` and
   `auth_service_claude_mcp_hub_allowed_users` (both or none) and runs playbook 59 from a
   checkout on `main`: `ansible-playbook infra/playbooks/59_app_services.yml`.
   - Secret format: `{bcrypt}$2y$10$` followed by 53 characters — the output of
     `htpasswd -B -C 10` without the `user:` prefix and without a trailing newline, plus the
     `{bcrypt}` id (`$2a$`/`$2b$` also work).
   - Allowlist: auth-service usernames, comma-separated, exact spelling and letter case.
2. Restart: `kubectl -n apps delete pod -l app=auth-service` (see "Restart service").
3. Verify the start-up log:
```bash
kubectl -n apps logs -l app=auth-service --tail=400 --request-timeout=10s | grep -E "claude-mcp-hub"
# expected: Seeded SSO client 'claude-mcp-hub' (first start with the secret only)
# not expected: Client 'claude-mcp-hub' has no allowed users configured; ...
```
   If `Seeded SSO client 'claude-mcp-hub'` is missing on the first start with the secret,
   check whether a device client uses that id (the seeder then skips the hub client):
```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -tAc \
  "SELECT client_kind FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub'"
# expected: sso
```

**Allowlist change:** change the SOPS value, run playbook 59, restart the pod. No SQL.

**Login refused** (`access_denied` after a successful login): log lines never name users.
Compare the SOPS allowlist value with the stored usernames:
```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -tAc "SELECT username FROM users"
```

**Secret rotation** (spec 080 §4.6 L5): the seeder never updates an existing row, so change
the row **and** the SOPS variable `auth_service_claude_mcp_hub_client_secret` (otherwise a
database restore or a reseed brings the old secret back), then remove and re-add the
connector in claude.ai. The owner inserts the new `{bcrypt}` value; it is never written to
the repository:
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
UPDATE oauth2_registered_client SET client_secret = '<{bcrypt} value>' WHERE client_id = 'claude-mcp-hub';
SQL
# expected: UPDATE 1
```

**Revoke the authorizations and the consent** (spec 080 §4.6 L4). Consents go first, so
the consent page is shown again at the next authorization; the next refresh gets
`400 invalid_grant`; access tokens already issued stay valid until `exp` (at most 10
minutes):
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM oauth2_authorization_consent
 WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
DELETE FROM oauth2_authorization
 WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
COMMIT;
SQL
```
The infrastructure incident runbook (`homelab` repository, `DEPLOYMENT.md`) carries the
same SQL and the other levels of spec 080 §4.6.

### Remove or rename the claude-mcp-hub client (also before reverting #107)

Required before reverting #107, deploying an older auth-service image, or removing or
renaming the `claude-mcp-hub` entry in `application.yaml` (or its
`access-token-audience`), once the client has been seeded. A seeded row without the code
and configuration that shape its tokens must not keep working. Spec 080 §4.6 "Disabling
and removing the hub client" (D55); the infrastructure runbook "Disable and remove the
`claude-mcp-hub` client" carries the same procedure.

Check first (read-only):
```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -tAc \
  "SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub'"
```
`0` means the client was never seeded: no step below is needed. Otherwise, in this order:

1. Owner go (every step below is an owner action or needs the owner's go).
2. Hub kill switch (spec 080 §4.6 L2 step 1):
```bash
kubectl -n apps patch secret mcp-hub-secrets --type merge -p '{"stringData":{"allowed-subjects":""}}'
kubectl -n apps delete pod -l app=mcp-hub
```
3. Remove **both** SOPS variables `auth_service_claude_mcp_hub_client_secret` and
   `auth_service_claude_mcp_hub_allowed_users` (with only one of them the play fails), then
   run playbook 59 from a checkout on `main`:
   `ansible-playbook infra/playbooks/59_app_services.yml` — expect the message "skipping
   the claude-mcp-hub keys in homelab-auth-secrets".
4. Remove both keys from the Secret (the playbook leaves existing keys in place), then list
   the key names only:
```bash
kubectl -n apps patch secret homelab-auth-secrets --type json -p '[{"op":"remove","path":"/data/claude-mcp-hub-client-secret"},{"op":"remove","path":"/data/claude-mcp-hub-allowed-users"}]'
kubectl -n apps get secret homelab-auth-secrets --request-timeout=10s -o json | jq '.data | keys'
# expect: neither claude-mcp-hub-client-secret nor claude-mcp-hub-allowed-users in the list
```
   From now on every start of auth-service sees a blank secret and cannot seed the client
   again, whatever image runs.
5. Remove the client with its consents and authorizations, in one transaction, the client
   row last (loading a consent fails for a missing client):
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM oauth2_authorization_consent
 WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
DELETE FROM oauth2_authorization
 WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub');
DELETE FROM oauth2_registered_client
 WHERE client_id = 'claude-mcp-hub';
COMMIT;
SQL
# expect BEGIN, three DELETE lines (the last one DELETE 1), COMMIT
```
6. Verify the row is gone:
```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -tAc \
  "SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub'"
# expect 0
```
7. Only then merge the revert, deploy an older image or change the configuration entry.
   A revert of #107 keeps `src/main/resources/db/migration/V8__oauth2_authorization_consent_timestamps.sql`:
   the migration is additive, and an older image starts on the migrated schema.

Why this order: the kill switch stops the hub while the identity-provider side is taken
apart; the Secret keys go before the SQL because a pod restart with the secret still
present would seed the client again. Access tokens issued before step 5 stay valid until
`exp` (at most 10 minutes), but the hub refuses them after step 2.

**Removing any other client row by hand:** delete its consents and authorizations first,
then the row, as in step 5.

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
| `CLAUDE_MCP_HUB_CLIENT_SECRET` | `homelab-auth-secrets` (`claude-mcp-hub-client-secret`) | No | `claude-mcp-hub` client secret, `{bcrypt}` cost 10; blank = client not seeded |
| `CLAUDE_MCP_HUB_ALLOWED_USERS` | `homelab-auth-secrets` (`claude-mcp-hub-allowed-users`) | No | Usernames allowed to use `claude-mcp-hub`, comma-separated, exact spelling; empty = everyone rejected |
| `SENTRY_DSN` | `sentry-dsn` | No | Sentry error tracking |

---

## Quick commands

```bash
# Status
kubectl get pods -n apps -l app=auth-service
kubectl rollout status deployment/auth-service -n apps

# Logs
kubectl logs -n apps deployment/auth-service --tail=100 -f

# Restart (not rollout restart; see Runbooks > Restart service)
kubectl -n apps delete pod -l app=auth-service

# Flux
flux get kustomizations -n flux-system
flux reconcile kustomization auth-service -n flux-system --with-source
```
