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

**Never edit or delete existing `V*.sql` migration files.** Flyway checksums will fail.

---

## Configuration Reference

| Env Var | K8s Source | Description |
|---------|-----------|-------------|
| `DB_USERNAME` | Secret `homelab-db-credentials` / key `username` | PostgreSQL username |
| `DB_PASSWORD` | Secret `homelab-db-credentials` / key `password` | PostgreSQL password |
| `APP_JWT_PRIVATE_KEY` | `file:/etc/secrets/private.pem` | RSA private key path (volume mount) |
| `APP_JWT_PUBLIC_KEY` | `file:/etc/secrets/public.pem` | RSA public key path (volume mount) |

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

Common causes: database unreachable, migration checksum mismatch (edited existing migration file).

### Service fails to start — RSA key error

```bash
kubectl logs -n apps deployment/auth-service | grep -i "rsa\|key\|pem"
kubectl get secret homelab-auth-rsa-keys -n apps
kubectl describe pod -n apps -l app=auth-service | grep -A5 Mounts
```

### Refresh tokens invalid after upgrade to V2 schema

After deploying the V2 migration, all previously stored refresh tokens are invalidated because the service now SHA-256 hashes tokens before storage. Users will need to re-authenticate. This is expected and one-time.

### Token cleanup scheduler not running

`TokenCleanupScheduler` purges expired refresh tokens every hour. If the `refresh_tokens` table grows unbounded, verify the scheduler is active:

```bash
kubectl logs -n apps deployment/auth-service | grep -i "purge\|cleanup\|scheduler"
```

Ensure `@EnableScheduling` is active on `AuthServiceApplication`.

### JWT validation failures in device-service or data-service

Downstream services fetch the JWKS from `http://auth-service.apps.svc.cluster.local:8080/api/v1/auth/jwks`.

Verify the endpoint is reachable from within the cluster:

```bash
kubectl run -n apps curl-test --image=curlimages/curl --restart=Never --rm -it -- \
  curl -s http://auth-service.apps.svc.cluster.local:8080/api/v1/auth/jwks
```
