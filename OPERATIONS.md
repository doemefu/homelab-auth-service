# OPERATIONS.md — homelab-auth-service

Runbooks and operational reference for auth-service on the K3s cluster.

---

## Service Runbooks

### Restart auth-service

```bash
kubectl rollout restart deployment/auth-service -n apps
kubectl rollout status deployment/auth-service -n apps
```

### View logs

```bash
kubectl logs -n apps deployment/auth-service --tail=100 -f
```

---

## Database Migrations

Flyway runs automatically on service startup. Migration scripts are in `src/main/resources/db/migration/`.

Migration history is tracked in the `flyway_schema_history_auth` table (custom name to avoid conflicts with other services sharing the same PostgreSQL instance).

No manual migration step is required. If a migration fails the service will refuse to start — check pod logs:

```bash
kubectl logs -n apps deployment/auth-service | grep -i flyway
```

Current migrations:
- **V1** — Initial schema: `users` + `refresh_tokens` tables
- **V2** — Widens `password_hash` to `VARCHAR(255)`, resizes `refresh_tokens.token` to `VARCHAR(64)` (SHA-256 hashes), converts all timestamps to `TIMESTAMPTZ`. Truncates existing refresh tokens (incompatible format after hashing change).
- **V3** — Creates `oauth2_authorization` and `oauth2_authorization_consent` tables for Spring Authorization Server token storage.
- **V4** — Drops the legacy `refresh_tokens` table.

**Never edit or delete existing `V*.sql` migration files.** Flyway checksums will fail.

### Deploying onto an existing schema without a Flyway history table

If the database already has tables (e.g., migrated from a pre-Flyway setup or the history table was accidentally dropped) Flyway will refuse to start with:

```
Found non-empty schema(s) "public" but no schema history table.
```

Set the following env vars in the K8s Secret or ConfigMap **for the first rollout only**, then remove them once the pod is healthy:

```bash
FLYWAY_BASELINE_ON_MIGRATE=true
FLYWAY_BASELINE_VERSION=0   # baselines before V1 so all migrations run; use only when auth-service tables don't exist yet
```

After the pod starts successfully, verify the history table was created:

```bash
kubectl exec -n apps deploy/auth-service -- \
  sh -c 'PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USERNAME -d homelabdb \
  -c "SELECT version, description, success FROM flyway_schema_history_auth ORDER BY installed_rank;"'
```

Then remove `FLYWAY_BASELINE_ON_MIGRATE` from the deployment. Leaving `true` permanently would silently re-baseline if the history table is ever dropped instead of failing loudly.

---

## Adding a New OIDC Client

1. Choose a client secret and prepare the encoded value for the K8s Secret.
   The env var must contain the full Spring Security encoded form:
   - Simplest (homelab): `{noop}<plaintext>` — no hashing, verified as-is
   - More secure: `{bcrypt}<bcrypt-hash>` — generate the hash with:
     ```bash
     htpasswd -bnBC 12 "" <your-secret> | tr -d ':\n'
     # prefix the output: {bcrypt}$2a$12$...
     ```

2. Store the encoded secret in a K8s Secret env var:
   ```bash
   kubectl patch secret homelab-auth-secrets -n apps \
     --type merge \
     -p '{"stringData":{"MY_NEW_CLIENT_SECRET":"{noop}<plaintext-secret>"}}'
   ```
   Then reference it in `k8s/deployment.yaml` under `env` as `MY_NEW_CLIENT_SECRET`.

3. Add the client configuration to `application.yaml` under `app.oidc.clients` (list format):
   ```yaml
   app:
     oidc:
       clients:
         - client-id: my-new-client
           client-secret: "${MY_NEW_CLIENT_SECRET}"
           redirect-uris:
             - "https://my-app.furchert.ch/login/oauth2/code/auth-service"
           scopes:
             - openid
             - profile
             - email
   ```

4. Restart the pod:
   ```bash
   kubectl rollout restart deployment/auth-service -n apps
   kubectl rollout status deployment/auth-service -n apps
   ```

---

## Rotating a Client Secret

1. Prepare the new encoded secret (the env var must include the `{id}` prefix):
   ```bash
   # Simplest — no hashing:
   # value to store: {noop}<new-plaintext-secret>
   #
   # More secure — BCrypt hash:
   htpasswd -bnBC 12 "" <new-secret> | tr -d ':\n'
   # prefix the output: {bcrypt}$2a$12$...
   ```

2. Update the K8s Secret with the new encoded value:
   ```bash
   kubectl patch secret homelab-auth-secrets -n apps \
     --type merge \
     -p '{"stringData":{"GRAFANA_CLIENT_SECRET":"{noop}<new-plaintext-secret>"}}'
   ```

4. Restart the pod:
   ```bash
   kubectl rollout restart deployment/auth-service -n apps
   ```

After restart, update the client configuration in the consuming service (Grafana, Home Assistant, etc.) to use the new secret.

---

## Integrating a Service with furchert.ch SSO

Use the OIDC discovery document to configure any OIDC-compatible client:

| Value | Description |
|-------|-------------|
| Discovery URL | `https://auth.furchert.ch/.well-known/openid-configuration` |
| Issuer | `https://auth.furchert.ch` |
| Client ID | assigned per client (e.g. `grafana`, `home-assistant`) |
| Client Secret | set via env var; obtain from operator |
| Scopes | `openid profile email` |
| Grant type | Authorization Code with PKCE |

### Grafana

Add to `grafana.ini` (or equivalent environment variables):

```ini
[auth.generic_oauth]
enabled = true
name = Homelab SSO
icon = signin
client_id = grafana
client_secret = ${GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET}
scopes = openid profile email
auth_url = https://auth.furchert.ch/oauth2/authorize
token_url = https://auth.furchert.ch/oauth2/token
api_url = https://auth.furchert.ch/userinfo
use_pkce = true
role_attribute_path = role == 'ADMIN' && 'Admin' || 'Viewer'
```

Set the env var in K8s:
```bash
kubectl patch secret grafana-secret -n monitoring \
  --type merge \
  -p '{"stringData":{"GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET":"<plaintext-secret>"}}'
```

### Home Assistant

In `configuration.yaml`:

```yaml
homeassistant:
  auth_providers:
    - type: homeassistant

http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 10.0.0.0/8

oidc:
  discovery_url: https://auth.furchert.ch/.well-known/openid-configuration
  client_id: home-assistant
  client_secret: !secret ha_oidc_client_secret
  scopes:
    - openid
    - profile
    - email
```

Add `ha_oidc_client_secret: <plaintext-secret>` to `secrets.yaml`.

### Other Services (template)

For any Spring Boot service using `spring-boot-starter-oauth2-client`:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          auth-service:
            client-id: my-service
            client-secret: ${MY_SERVICE_CLIENT_SECRET}
            authorization-grant-type: authorization_code
            scope: openid,profile,email
        provider:
          auth-service:
            issuer-uri: https://auth.furchert.ch
```

---

## Configuration Reference

| Env Var | K8s Source | Description |
|---------|-----------|-------------|
| `DB_USERNAME` | Secret `homelab-db-credentials` / key `username` | PostgreSQL username |
| `DB_PASSWORD` | Secret `homelab-db-credentials` / key `password` | PostgreSQL password |
| `APP_JWT_PRIVATE_KEY` | `file:/etc/secrets/private.pem` | RSA private key path (volume mount) |
| `APP_JWT_PUBLIC_KEY` | `file:/etc/secrets/public.pem` | RSA public key path (volume mount) |
| `GRAFANA_CLIENT_SECRET` | Secret `homelab-auth-secrets` / key `grafana-client-secret` | Grafana OIDC client secret (plaintext) |
| `HA_CLIENT_SECRET` | Secret `homelab-auth-secrets` / key `ha-client-secret` | Home Assistant OIDC client secret (plaintext) |
| `DEVICE_SERVICE_CLIENT_SECRET` | Secret `homelab-auth-secrets` / key `device-service-client-secret` | device-service OIDC client secret (plaintext) |
| `N8N_CLIENT_SECRET` | Secret `homelab-auth-secrets` / key `n8n-client-secret-authservice` | n8n OIDC client secret for auth-service (must include `{id}` prefix) |

RSA keys are mounted from Secret `homelab-auth-rsa-keys` at `/etc/secrets/`.

The K8s deployment uses image tag `:<git-sha>` (not `:latest`). Update `k8s/deployment.yaml` with the correct SHA from the CI build before applying.

---

## RSA Key Rotation

1. Generate a new key pair locally:
   ```bash
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout -out public.pem
   ```

2. Recreate the K8s Secret:
   ```bash
   kubectl delete secret homelab-auth-rsa-keys -n apps
   kubectl create secret generic homelab-auth-rsa-keys -n apps \
     --from-file=private.pem=./private.pem \
     --from-file=public.pem=./public.pem
   ```

3. Restart the service:
   ```bash
   kubectl rollout restart deployment/auth-service -n apps
   ```

4. **Side effects:**
   - All existing access tokens are immediately invalidated (new key cannot verify old signatures)
   - Downstream services (device-service, data-service) cache the JWKS by `kid` — they will pick up the new public key on their next JWKS fetch or pod restart. If you change the `kid` value in the future, update `JwtService.KEY_ID`.
   - Consider revoking all refresh tokens: `DELETE FROM refresh_tokens;`

---

## Troubleshooting

### Service fails to start — Flyway migration error

```bash
kubectl logs -n apps deployment/auth-service | grep -i "flyway\|migration\|error"
```

Common causes:
- **Database unreachable** — check `DB_URL` env var and PostgreSQL pod status
- **Checksum mismatch** — an existing `V*.sql` file was edited; restore the original or repair with `flyway repair`
- **Non-empty schema, no history table** — see *Deploying onto an existing schema without a Flyway history table* above

### Service fails to start — RSA key error

```bash
kubectl logs -n apps deployment/auth-service | grep -i "rsa\|key\|pem"
kubectl get secret homelab-auth-rsa-keys -n apps
kubectl describe pod -n apps -l app=auth-service | grep -A5 Mounts
```

### OAuth2 authorization cleanup scheduler not running

`TokenCleanupScheduler` purges expired OAuth2 authorizations from the `oauth2_authorization` table every hour. If the table grows unbounded, verify the scheduler is active:

```bash
kubectl logs -n apps deployment/auth-service | grep -i "purge\|cleanup\|scheduler"
```

Ensure `@EnableScheduling` is active on `AuthServiceApplication`.

### JWT validation failures in device-service or data-service

Downstream services fetch the JWKS from `http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks`.

Verify the endpoint is reachable from within the cluster:

```bash
kubectl run -n apps curl-test --image=curlimages/curl --restart=Never --rm -it -- \
  curl -s http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks
```

### OIDC login page not reachable / redirect loop

Check that `app.oidc.issuer` in `application.yaml` matches the exact public hostname used by the client. A mismatch causes token validation to fail with `iss` claim errors.

```bash
kubectl logs -n apps deployment/auth-service | grep -i "issuer\|oidc\|oauth2"
```

Also verify `server.forward-headers-strategy=native` is set — the issuer URL is constructed from the `X-Forwarded-*` headers injected by Cloudflare Tunnel / Traefik.
