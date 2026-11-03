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
| `homelab-auth-secrets` | Client secrets for Grafana, Home Assistant, device-service, LiteLLM; optional `claude-mcp-hub-client-secret`, `claude-mcp-hub-allowed-users`, `claude-club-mcp-client-secret`, `claude-club-mcp-allowed-users` | OIDC client auth |
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
  --from-literal=grafana-client-secret='{bcrypt}<hash>' \
  --from-literal=ha-client-secret='{bcrypt}<hash>' \
  --from-literal=device-service-client-secret='{bcrypt}<hash>' \
  --from-literal=litellm-client-secret-authservice='{bcrypt}<hash>'
rm private.pem public.pem
```

   Each client secret value is `{bcrypt}` plus a cost-10 bcrypt hash of the plaintext the client uses (see "Add new
   OIDC client"). Single quotes keep the shell from expanding the `$` signs in the hash. Values with another encoding
   (for example the plaintext `{noop}`) still work but are logged as a WARN at every start (#100).

   Optional keys in `homelab-auth-secrets` for the login-event outbox (NM-4, see `INTERFACES.md` §2 "data-service"):
   `data-service-client-secret` (today `{noop}<secret>` from playbook 59, deprecated and logged as a WARN; target
   `{bcrypt}` via homelab#154) and `login-event-hmac-key` (at least 32 characters, e.g. `openssl rand -hex 32`).
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

### Container hardening and writable paths

The pod runs as uid/gid 100/101 (the image's `appuser`) with `readOnlyRootFilesystem`, all capabilities dropped, no privilege escalation and the `RuntimeDefault` seccomp profile. `/tmp` (disk-backed `emptyDir`, 64Mi) is the only writable path (Tomcat work dirs, `hsperfdata`). The RSA keys are read from the read-only Secret mount `/etc/secrets`; nothing is written there. Anything new that writes to disk (log files, heap dumps) must target `/tmp` or gets a new volume. The pod mounts no ServiceAccount token (`automountServiceAccountToken: false`); auth-service never calls the Kubernetes API.

After a merge Flux rolls the Deployment out; the startup probe allows 300 s:

```bash
kubectl -n apps rollout status deploy/auth-service --timeout=400s
```

If this stalls, revert the change (`git revert` the merge commit on `main`). With one replica the default RollingUpdate gives an effective `maxUnavailable` of 0 (25% rounds down), so the old pod keeps serving while the new one fails to become ready.

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

The signing key and its JWK `kid` must change together: consumers cache keys by `kid` (mcp-hub up to 1 h, Spring
resource servers about 5 min) and only refetch the JWKS for an unknown `kid`. Never reuse a `kid` for another key.
In production the key comes from the owner's encrypted variables (`auth_service_rsa_private_key` /
`auth_service_rsa_public_key`) through infrastructure playbook 59 into `homelab-auth-rsa-keys`; a key created with
`kubectl create secret` is overwritten by the next playbook-59 run. The `kid` is `APP_JWT_KEY_ID` (default
`auth-service-v1`). Order (owner actions, each with its own go):

1. Open a pull request that sets `APP_JWT_KEY_ID` to the next unused value (for example `auth-service-v2`) in
   `k8s/deployment.yaml`. Do not merge it yet.
2. Generate a 3072-bit key in PKCS#8 (the service reads only `BEGIN PRIVATE KEY`; `openssl genrsa` writes PKCS#1 under
   LibreSSL and OpenSSL 1.x):
   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem
   openssl pkey -in private.pem -pubout -out public.pem
   head -1 private.pem   # must be: -----BEGIN PRIVATE KEY-----
   ```
   Put both into the encrypted variables, then delete the local files.
3. Run playbook 59. The mounted files change; the running pod keeps signing with the old key from memory.
4. Merge the `kid` pull request right away. The Flux rollout starts a pod that loads the new key with the new `kid`.
   Between steps 3 and 4 any restart (another merge, a node reset) would sign with the new key under the old `kid`, so
   keep that window short and merge nothing else in it (`flux reconcile kustomization auth-service -n flux-system`
   right after the merge shortens it).
5. Verify: `curl -s https://auth.furchert.ch/oauth2/jwks | jq -r '.keys[].kid'` shows the new `kid`; the pod is new
   and its start-up log has no key error; a fresh sign-in to furchert-ch `/dashboard` and a claude.ai connector call
   work. Rollback: put the old key pair back into the encrypted variables, run playbook 59, revert the `kid` pull
   request.

Effect: access and ID tokens signed with the old key fail at every consumer once it drops the old `kid`; refresh
tokens are opaque database rows and keep working, so clients recover with their next refresh. RP-initiated logout
with an old `id_token_hint` keeps working while its authorization row exists (about 7 days); after the row is purged
the hint fails the signature check and `/connect/logout` answers `400` without ending the IdP session.

### Add new OIDC client
1. Generate the encoded secret. Create the plaintext, e.g. `openssl rand -hex 32` (bcrypt uses only the first 72
   bytes). `htpasswd` prompts for it, so it stays out of the shell history:
   `printf '{bcrypt}%s\n' "$(htpasswd -nBC 10 "" | tr -d ':\n')"`. The client application gets the plaintext; auth-service gets the `{bcrypt}` value.
2. Update secret (single quotes, the hash contains `$`): `kubectl patch secret homelab-auth-secrets -n apps --type merge -p '{"stringData":{"new-client-secret":"<{bcrypt} value>"}}'`
3. Add client config to `application.yaml`
4. Add env var reference to `k8s/deployment.yaml`
5. Restart service (see "Restart service")

### Client secret not stored as {bcrypt}

At start-up `StaticClientSeeder` logs one WARN per configured SSO client whose secret is not a `{bcrypt}` hash, for
example the plaintext `{noop}` encoding (#100). The line names the client and where the weak value sits, never the
value:

```bash
kubectl -n apps logs -l app=auth-service --tail=-1 --request-timeout=10s | grep "is not a {bcrypt} hash"
# SSO client 'litellm': client secret (configured value) is not a {bcrypt} hash; ...
```

- **configured value:** the env var (Secret key in `homelab-auth-secrets`) is not `{bcrypt}`. A database restore or a
  reseed would store that value again.
- **stored row:** `oauth2_registered_client.client_secret` is not `{bcrypt}`. Spring Authorization Server re-encodes a
  stored secret to `{bcrypt}` on the client's first successful authentication, so this means the client has not
  authenticated since it was seeded.

Check the encodings without printing any secret characters (only the `{id}` prefix):

```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -tAc \
  "SELECT client_id, substring(client_secret from '^[{][^}]*[}]') FROM oauth2_registered_client WHERE client_kind = 'sso' ORDER BY client_id"
```

Fix, per client (owner action; the plaintext the client application uses does not change):

1. Create the `{bcrypt}` value from the client's current plaintext as in "Add new OIDC client" step 1. Hash the
   plaintext **without** any `{noop}` prefix. Before storing it, check it against the plaintext (`htpasswd -v`
   prompts and prints `Password for user x correct.`):
```bash
f=$(mktemp); printf 'x:%s\n' '<hash without the {bcrypt} prefix>' > "$f"; htpasswd -v "$f" x; rm -f "$f"
```
2. Configured value: Grafana and Home Assistant keys are written verbatim by playbook 59 from the owner's encrypted
   variables `auth_service_grafana_client_secret` / `auth_service_ha_client_secret`; change the variable and run
   playbook 59 (owner). A direct `kubectl patch` of the key is reverted by the next playbook run. For
   `device-service`, `litellm`, `furchert-ch` and `data-service` playbook 59 adds the `{noop}` prefix itself
   and gives the consumer the same variable, so their switch needs the playbook change of homelab#154 first. The
   consumer keeps the plaintext in its own Secret key.
3. Stored row (only when the WARN names it): trigger one login or token request of the client. Spring Authorization
   Server then re-encodes the row with a fresh `{bcrypt}` hash, and a wrong hash cannot be stored. Only for a client
   that cannot authenticate, update the row by hand (the seeder never updates rows). Quote the heredoc so the shell
   keeps the `$` signs, and use a value checked in step 1; a wrong value breaks the client until it is corrected:
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
UPDATE oauth2_registered_client SET client_secret = '<{bcrypt} value>' WHERE client_id = '<client-id>' AND client_kind = 'sso';
SQL
# expected: UPDATE 1
```
4. Restart (see "Restart service") and check that the WARN line for that client is gone. Then test one login or token
   request of the client.

### Rotate an SSO client secret

Registered clients live in `oauth2_registered_client` (Flyway V5); the seeder never updates an existing row, and the
row is read on every client authentication (no cache), so an `UPDATE` takes effect at once. All steps are owner
actions; playbook runs and restarts need a go. Order:

1. Create the new plaintext and its `{bcrypt}` value, and check the hash, as in "Add new OIDC client" step 1 and
   "Client secret not stored as {bcrypt}" step 1.
2. Put the new values into the encrypted variables and run playbook 59 (it updates the Kubernetes Secrets; no pod
   restarts):
   - `grafana`, `homeassistant`: the auth-service key (`auth_service_grafana_client_secret` /
     `auth_service_ha_client_secret`) gets the `{bcrypt}` value. Their own configuration (set in the Grafana and Home
     Assistant UIs) gets the plaintext in step 4, not now, because a UI change applies at once.
   - `device-service`, `litellm`, `furchert-ch`, `data-service`: one variable feeds both sides today (playbook 59
     adds `{noop}` for auth-service, the consumer gets the plaintext), so set it to the new plaintext. homelab#154
     splits them so that auth-service gets a `{bcrypt}` value.
   - `claude-mcp-hub`, `claude-club-mcp`: see their own sections below.
3. Right after the playbook (merge nothing in between: a consumer pod restarted now would already use the new
   plaintext against the old row), update the row with the `{bcrypt}` value (quoted heredoc, the hash contains `$`);
   from now on the old secret fails:
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
UPDATE oauth2_registered_client SET client_secret = '<{bcrypt} value>' WHERE client_id = '<client-id>' AND client_kind = 'sso';
SQL
# expected: UPDATE 1
```
4. At once: restart the consumer so it reads the new plaintext (Flux apps: `kubectl -n apps delete pod -l app=<name>`),
   or for Grafana and Home Assistant enter it in their UI. A consumer that kept retrying the old secret may get `429`
   for up to 5 minutes ("Login throttle").
5. Verify with one login or token request of the client (and its logs show no `invalid_client`).
6. Optional for `grafana`/`homeassistant`: restart auth-service (see "Restart service") so it reads the new configured
   value and its start-up WARN for that client disappears. The four shared-variable clients keep a `{noop}` configured
   value until homelab#154.

### Revoke a device client

What it does today: no new tokens for that client. Tokens already issued stay valid until their `exp` (the client's
stored access-token TTL, 3600 s by default from `app.oidc.device-clients.access-token-ttl-seconds`) at any resource
server that accepts them. Mosquitto does not check device tokens yet (it accepts anonymous connections until
infrastructure `docs/053-mqtt-device-authentication.md` ships), so revocation does not cut a device off the broker.

1. Preferred: furchert-ch `/dashboard/auth`, tab Clients, as a signed-in ADMIN: delete the client.
2. Fallback (owner, psql). Only device rows, in one transaction:
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM oauth2_authorization WHERE registered_client_id =
  (SELECT id FROM oauth2_registered_client WHERE client_id = '<client-id>' AND client_kind = 'device');
DELETE FROM oauth2_authorization_consent WHERE registered_client_id =
  (SELECT id FROM oauth2_registered_client WHERE client_id = '<client-id>' AND client_kind = 'device');
DELETE FROM oauth2_registered_client WHERE client_id = '<client-id>' AND client_kind = 'device';
COMMIT;
SQL
# expected: the last DELETE reports DELETE 1
```
3. Verify with "Inspect registered clients": the client is gone. `DELETE /api/v1/clients/{clientId}` answers `204`
   also for an unknown id or an SSO client id (nothing deleted), so a typo looks like success.

Cutting off tokens that are already issued needs an RSA key rotation, which invalidates the access and ID tokens of
every client (see "RSA key rotation"); use it only as a last resort.

### Inspect registered clients

Prints the encoding prefix of each secret, never secret characters:
```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -c \
  "SELECT client_id, client_kind, authorization_grant_types, client_authentication_methods, substring(client_secret from '^[{][^}]*[}]') AS secret_encoding FROM oauth2_registered_client ORDER BY client_kind, client_id"
```

### client_kind cache

`ClientKindLookup` keeps each client's `client_kind` in memory; it only decides whether a `client_credentials` token
gets the `device_id` claim. A missing row is not cached, so new clients are seen at once. After a manual change of
`client_kind` on an existing row, restart auth-service (see "Restart service"); the restart also clears the login
throttle's counters.

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
   If `Seeded SSO client 'claude-mcp-hub'` is missing on the first start with the secret and
   the log shows `SSO client 'claude-mcp-hub' not seeded: another registered client already
   uses this client id`, a device client holds that id and the seeder skips the hub client.
   Check the row:
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
`0` means the client was never seeded: no step below is needed. Otherwise, in this order.
Every step needs the owner's go.

1. Hub kill switch (spec 080 §4.6 L2 step 1):
```bash
kubectl -n apps patch secret mcp-hub-secrets --type merge -p '{"stringData":{"allowed-subjects":""}}'
kubectl -n apps delete pod -l app=mcp-hub
```
2. Remove **both** SOPS variables `auth_service_claude_mcp_hub_client_secret` and
   `auth_service_claude_mcp_hub_allowed_users` (with only one of them the play fails), then
   run playbook 59 from a checkout on `main`:
   `ansible-playbook infra/playbooks/59_app_services.yml` — expect the message "skipping
   the claude-mcp-hub keys in homelab-auth-secrets".
3. Remove each key with its own JSON patch, only if it still exists (the playbook leaves
   existing keys in place), then list the key names only:
```bash
# jq exit 0 = key present, 1 = already gone, anything else = the Secret could not be read.
for k in claude-mcp-hub-client-secret claude-mcp-hub-allowed-users; do
  kubectl -n apps get secret homelab-auth-secrets --request-timeout=10s -o json | jq -e --arg k "$k" '.data[$k]' >/dev/null
  case $? in
    0) kubectl -n apps patch secret homelab-auth-secrets --type json -p "[{\"op\":\"remove\",\"path\":\"/data/$k\"}]" ;;
    1) echo "$k is already gone - skipped" ;;
    *) echo "could not read homelab-auth-secrets - stop and check cluster access before going on"; break ;;
  esac
done
kubectl -n apps get secret homelab-auth-secrets --request-timeout=10s -o json | jq '.data | keys'
# expect: neither claude-mcp-hub-client-secret nor claude-mcp-hub-allowed-users in the list
```
   Off-LAN (one-shot kubectl over SSH, see the infrastructure `DEPLOYMENT.md`):
```bash
for k in claude-mcp-hub-client-secret claude-mcp-hub-allowed-users; do
  ssh -i ~/.ssh/homelab -o IdentitiesOnly=yes -o ProxyCommand="cloudflared access ssh --hostname %h" ansible@ssh.furchert.ch \
    'sudo k3s kubectl -n apps get secret homelab-auth-secrets -o json' | jq -e --arg k "$k" '.data[$k]' >/dev/null
  case $? in
    0) ssh -i ~/.ssh/homelab -o IdentitiesOnly=yes -o ProxyCommand="cloudflared access ssh --hostname %h" ansible@ssh.furchert.ch \
         "sudo k3s kubectl -n apps patch secret homelab-auth-secrets --type json -p '[{\"op\":\"remove\",\"path\":\"/data/$k\"}]'" ;;
    1) echo "$k is already gone - skipped" ;;
    *) echo "could not read homelab-auth-secrets - stop and check the SSH access before going on"; break ;;
  esac
done
ssh -i ~/.ssh/homelab -o IdentitiesOnly=yes -o ProxyCommand="cloudflared access ssh --hostname %h" ansible@ssh.furchert.ch \
  'sudo k3s kubectl -n apps get secret homelab-auth-secrets -o json' | jq '.data | keys'
```
   From now on every start of auth-service sees a blank secret and cannot seed the client
   again, whatever image runs.
4. Remove the client with its consents and authorizations, in one transaction, the client
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
5. Verify the row is gone:
```bash
kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -tAc \
  "SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'claude-mcp-hub'"
# expect 0
```
6. Only then merge the revert, deploy an older image or change the configuration entry.
   A revert of #107 keeps `src/main/resources/db/migration/V8__oauth2_authorization_consent_timestamps.sql`:
   the migration is additive, and an older image starts on the migrated schema.

Why this order: the kill switch stops the hub while the identity-provider side is taken
apart; the Secret keys go before the SQL because a pod restart with the secret still
present would seed the client again. Access tokens issued before step 4 stay valid until
`exp` (at most 10 minutes), but the hub refuses them after step 1.

### Enable, change or revoke the claude-club-mcp client

The club-assistant MCP connector (club-assistant D67, `club:read`, audience
`https://club-mcp.furchert.ch/mcp`) is a second client of the same kind as `claude-mcp-hub`; see
`INTERFACES.md` §2 "claude-club-mcp". Everything in the hub sections above applies with the client id,
SOPS variables, Secret keys and env vars renamed as below. Every step is an owner action or needs the
owner's go.

1. The owner sets the SOPS variables `auth_service_claude_club_mcp_client_secret` (`{bcrypt}` hash,
   cost 10, same format as the hub's) and `auth_service_claude_club_mcp_allowed_users` (comma-separated
   auth-service usernames, exact spelling; both or none), then runs playbook 59 from a checkout on
   `main`. The playbook must already write the Secret keys `claude-club-mcp-client-secret` and
   `claude-club-mcp-allowed-users` (infrastructure change of the same milestone); without them the
   client is silently not seeded.
2. Restart: `kubectl -n apps delete pod -l app=auth-service`.
3. Verify: `kubectl -n apps logs -l app=auth-service --tail=400 --request-timeout=10s | grep -E "claude-club-mcp"`
   expects no "has no allowed users configured" warning. The `Seeded SSO client 'claude-club-mcp'` line appears
   only on the **first** registration; the seeder skips an existing row (debug log only), so after a later
   change verify the row instead (read-only):
   `kubectl -n apps exec postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -c "SELECT client_id, scopes FROM oauth2_registered_client WHERE client_id = 'claude-club-mcp';"`
4. claude.ai: Settings, Connectors, add a custom connector with the club MCP URL
   `https://club-mcp.furchert.ch/mcp`, open "Advanced settings" and enter the OAuth client id
   `claude-club-mcp` and the plaintext secret (the plaintext exists only there; the repository and the
   cluster hold the hash). Connecting shows the consent page with scope `club:read`.

**Allowlist change:** change the SOPS value, run playbook 59, restart the pod. No SQL. The allowlist is
checked on authorization requests only, never on refresh (`ClientUserAllowlist`): removing a user does
**not** end access they already have — their refresh token keeps minting club access tokens. To end it,
also revoke that user's club authorizations (see "Revoke the authorizations and the consent" below), or
remove their subject from the club MCP server's allowlist (`club_mcp_allowed_subjects` /
`mcp_limits.allowed_subjects` in club-assistant, D67), which refuses their tokens at the server.

**Secret rotation:** the seeder never updates an existing row, so change the row and the SOPS variable,
then remove and re-add the connector in claude.ai:
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
UPDATE oauth2_registered_client SET client_secret = '<{bcrypt} value>' WHERE client_id = 'claude-club-mcp';
SQL
# expected: UPDATE 1
```

**Revoke the authorizations and the consent** (next refresh gets `400 invalid_grant`; access tokens
already issued stay valid until `exp`, at most 10 minutes):
```bash
kubectl -n apps exec -i postgresql-0 -c postgresql -- psql -U postgres -d homelabdb -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM oauth2_authorization_consent
 WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-club-mcp');
DELETE FROM oauth2_authorization
 WHERE registered_client_id = (SELECT id FROM oauth2_registered_client WHERE client_id = 'claude-club-mcp');
COMMIT;
SQL
```
Further levels: remove the subject from the club MCP server's own subject allowlist (independent of this
service), or remove the client entirely.

### Login throttle (#104)

`POST /login` and client authentication are throttled in memory (contract: `INTERFACES.md`, Important Notes 5).
A lock logs one WARN without username or IP (a client lock names the client id):

```bash
kubectl -n apps logs -l app=auth-service --tail=-1 --request-timeout=10s | grep "Login throttle:"
# Login throttle: username locked for 300 s after 10 failed attempts
# Login throttle: client 'device-service' locked for 300 s after 10 failed attempts
# Login throttle: client 'device-service' in strict mode for 300 s after 50 failed attempts from all sources (one attempt at a time per source, rejected after one failure)
```

- Every minute with rejections: `Login throttle: rejected <n> attempts since the last report (username: <a> locked, <b> in-flight bound, <c> strict mode, <d> overflow bound (<e> attempts on overflow keys); ...)` (counts only).
- **Unlock early:** restart the pod (see "Restart service"). That clears every counter, the known-good list and the
  client fingerprints.
- **Client locked after a secret rotation:** a client that kept retrying with its old secret may get `429` for up to
  5 minutes; it recovers by itself once it uses the new secret after the lock.
- **Kill switch:** add `APP_LOGIN_THROTTLE_ENABLED` with value `"false"` to the container `env` in
  `k8s/deployment.yaml` (pull request, merge, Flux applies it). Thresholds can be changed the same way, for example
  `APP_LOGIN_THROTTLE_USER_MAX_FAILURES`; durations need a unit (`15m`), and values under 1 s fail start-up.
- **Owner kept out right after a restart:** a restart (every merge) empties the known-network list, so a targeted
  attack on the owner's username can block new logins from every network for as long as it runs. Recovery: set
  the kill switch by pull request (the GitHub web UI needs no auth-service login), or raise
  `APP_LOGIN_THROTTLE_USER_MAX_FAILURES` the same way.
- **Rollback:** `git revert` the merge commit on `main`; CI builds the image and Flux rolls it out.
- **Live check:** the login form needs a session cookie and its CSRF token, and the Cloudflare edge rule allows 5
  requests per 10 s per IP, so space attempts at least 3 s apart. From the home network every failure also counts
  for the home IP (20 per 15 min, then 15 min lock, and the known-good exemption does not lift an IP lock when the
  username is locked too), so run such a test at most once per 15 minutes or from another network. Failed test
  logins appear as login events in data-service.
- The edge rule of spec 080 §4.7 (D32) stays; it bounds bcrypt CPU per source address, which the in-app throttle
  does not.

### Remove or rename the claude-club-mcp client

Same procedure as "Remove or rename the claude-mcp-hub client" with these differences: skip the hub kill
switch (step 1) and instead empty the club MCP server's subject allowlist and restart it; the SOPS
variables are `auth_service_claude_club_mcp_client_secret` and `auth_service_claude_club_mcp_allowed_users`
(remove both); the Secret keys are `claude-club-mcp-client-secret` and `claude-club-mcp-allowed-users`;
the SQL targets `client_id = 'claude-club-mcp'`. Required before removing or renaming its
`application.yaml` entry or its `access-token-audience`, once the client has been seeded (the
audience-bound marker makes a seeded row fail closed without its configuration).

**Removing any other client row by hand:** delete its consents and authorizations first,
then the row, as in step 4.

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
| `LITELLM_CLIENT_SECRET` | `homelab-auth-secrets` | Yes | LiteLLM OIDC client secret |
| `CLAUDE_MCP_HUB_CLIENT_SECRET` | `homelab-auth-secrets` (`claude-mcp-hub-client-secret`) | No | `claude-mcp-hub` client secret, `{bcrypt}` cost 10; blank = client not seeded |
| `CLAUDE_MCP_HUB_ALLOWED_USERS` | `homelab-auth-secrets` (`claude-mcp-hub-allowed-users`) | No | Usernames allowed to use `claude-mcp-hub`, comma-separated, exact spelling; empty = everyone rejected |
| `CLAUDE_CLUB_MCP_CLIENT_SECRET` | `homelab-auth-secrets` (`claude-club-mcp-client-secret`) | No | `claude-club-mcp` client secret, `{bcrypt}` cost 10; blank = client not seeded |
| `CLAUDE_CLUB_MCP_ALLOWED_USERS` | `homelab-auth-secrets` (`claude-club-mcp-allowed-users`) | No | Usernames allowed to use `claude-club-mcp`, comma-separated, exact spelling; empty = everyone rejected |
| `SENTRY_DSN` | `sentry-dsn` | No | Sentry error tracking |
| `APP_JWT_KEY_ID` | Config | No | JWK `kid` of the signing key (default `auth-service-v1`); bump on every key rotation, never blank |
| `APP_LOGIN_THROTTLE_ENABLED` | Config | No | `false` disables the failed-attempt throttle (#104); default `true` |

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
