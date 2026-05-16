# homelab-auth-service — Deployment & Operations

This document provides comprehensive deployment instructions, infrastructure requirements, and operational guidance for auth-service.

---

## Table of Contents

1. [Infrastructure Requirements](#1-infrastructure-requirements)
2. [Resource Requirements](#2-resource-requirements)
3. [Dependencies](#3-dependencies)
4. [Deployment Methods](#4-deployment-methods)
5. [Step-by-Step Deployment Guide](#5-step-by-step-deployment-guide)
6. [Post-Deployment Verification](#6-post-deployment-verification)
7. [Health Checks & Monitoring](#7-health-checks--monitoring)
8. [Runbooks & Common Operations](#8-runbooks--common-operations)
9. [Troubleshooting Guide](#9-troubleshooting-guide)
10. [Security Considerations](#10-security-considerations)

---

## 1. Infrastructure Requirements

### Kubernetes Cluster

- **Provider:** K3s (lightweight Kubernetes for edge/IoT)
- **Namespace:** `apps`
- **Nodes:** ARM64 (raspi5, raspi4) with future amd64 support (mba1, mba2)

**Namespace Setup:**
```bash
kubectl create namespace apps
```

### Networking

- **Ingress:** Cloudflare Tunnel (recommended) with `cloudflared` pod in `platform` namespace
- **DNS:** Public DNS record pointing to Cloudflare Tunnel
- **Cluster-internal:** `auth-service.apps.svc.cluster.local:8080`

**Cloudflare Tunnel Configuration:**
Add auth-service to the cloudflared ingress list in `infra/playbooks/40_platform.yml`:

```yaml
- hostname: auth.furchert.ch
  service: http://auth-service.apps.svc.cluster.local:8080
```

Apply with:
```bash
ansible-playbook infra/playbooks/40_platform.yml
```

### Storage

- **Requirements:** None (stateless service)
- **Notes:** RSA keys and configuration are mounted from Kubernetes Secrets

---

## 2. Resource Requirements

### Container Resources

The service runs as a single pod (replicas: 1) due to Spring Authorization Server's in-memory session storage.

| Resource | Request | Limit | Notes |
|----------|---------|-------|-------|
| CPU | 100m | 500m | Sufficient for OIDC flow and token validation |
| Memory | 256Mi | 512Mi | Includes JVM overhead |

**CPU:** 0.1 to 0.5 CPU cores
**Memory:** 256MB requested, 512MB maximum

### Multi-Architecture Support

The cluster includes both ARM64 (Raspberry Pi) and AMD64 (Intel) nodes. The Docker image supports both architectures:

- `linux/arm64` — For Raspberry Pi nodes
- `linux/amd64` — For Intel Mac/Linux nodes

**Verify image architecture:**
```bash
docker buildx imagetools inspect ghcr.io/doemefu/homelab-auth-service:main-YYYYMMDDTHHmmss
```

---

## 3. Dependencies

### External Dependencies

| Dependency | Type | Source | Notes |
|-------------|------|--------|-------|
| PostgreSQL | Database | `postgresql.apps.svc.cluster.local:5432` | Database `homelabdb` |
| Cloudflare Tunnel | Ingress | `platform` namespace | Managed by `cloudflared` pod |

### Kubernetes Secrets

All secrets **must** exist in the `apps` namespace before first deployment.

| Secret Name | Purpose | Keys | Required |
|-------------|---------|------|----------|
| `homelab-db-credentials` | Database credentials | `username`, `password` | Yes |
| `homelab-auth-rsa-keys` | RSA key pair | `private.pem`, `public.pem` | Yes |
| `homelab-auth-secrets` | OIDC client secrets | `grafana-client-secret`, `ha-client-secret`, `device-service-client-secret`, `n8n-client-secret-authservice`, `litellm-client-secret-authservice` | Yes |
| `sentry-dsn` | Error tracking | `dsn` | No (optional) |

### Database

- **Engine:** PostgreSQL (shares instance with other homelab services)
- **Database:** `homelabdb`
- **Schema:** `public`
- **Flyway History Table:** `flyway_schema_history_auth` (custom name to avoid conflicts)

---

## 4. Deployment Methods

### Production: Flux CD (Automated)

**auth-service uses Flux CD for fully automated deployments.**

- **Trigger:** Push to `main` branch
- **CI:** GitHub Actions builds multi-arch Docker image
- **CD:** Flux CD detects new image, updates `k8s/deployment.yaml`, rolls out to cluster

**Cycle:**
1. Code pushed to `main`
2. GitHub Actions runs `./mvnw verify` (tests)
3. If tests pass: builds Docker image with tags:
   - `${git-sha}` — Content-addressable tag
   - `main-YYYYMMDDTHHmmss` — Timestamp tag for Flux CD
4. Flux CD detects new `main-*` tag within 5 minutes
5. Flux CD commits updated tag to `k8s/deployment.yaml`
6. Kubernetes rolls out new pod automatically

**Manually triggering Flux reconciliation:**
```bash
# Check status
flux get kustomizations -n flux-system
flux get image updates -n flux-system

# Force reconciliation
flux reconcile kustomization auth-service -n flux-system --with-source

# Suspend automation (emergency)
flux suspend image update auth-service -n flux-system

# Resume automation
flux resume image update auth-service -n flux-system
```

### Manual: kubectl apply

**Not recommended for production** (Flux CD will overwrite). Use for development/testing only.

```bash
# Apply manifests
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Or use kustomize
kubectl apply -k k8s/

# Check rollout
kubectl rollout status deployment/auth-service -n apps
```

---

## 5. Step-by-Step Deployment Guide

### First-Time Deployment

#### Step 1: Ensure Infrastructure is Ready

```bash
# Check nodes are Ready
kubectl get nodes

# Check PostgreSQL is running
kubectl get pods -n apps -l app=postgresql

# Ensure namespace exists
kubectl get namespace apps
```

#### Step 2: Create Required Secrets

**Database Credentials:**
```bash
kubectl create secret generic homelab-db-credentials -n apps \
  --from-literal=username=<db-username> \
  --from-literal=password=<db-password>
```

**RSA Keys:**
```bash
# Generate key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Create secret
kubectl create secret generic homelab-auth-rsa-keys -n apps \
  --from-file=private.pem=./private.pem \
  --from-file=public.pem=./public.pem

# Clean up local files
rm private.pem public.pem
```

**OIDC Client Secrets:**
```bash
# Using {noop} encoding for plaintext secrets (homelab convention)
kubectl create secret generic homelab-auth-secrets -n apps \
  --from-literal=grafana-client-secret="{noop}<grafana-secret>" \
  --from-literal=ha-client-secret="{noop}<ha-secret>" \
  --from-literal=device-service-client-secret="{noop}<device-secret>" \
  --from-literal=n8n-client-secret-authservice="{noop}<n8n-secret>" \
  --from-literal=litellm-client-secret-authservice="{noop}<litellm-secret>"
```

**Optional: Sentry (Error Tracking):**
```bash
kubectl create secret generic sentry-dsn -n apps \
  --from-literal=dsn=<your-sentry-dsn>
```

#### Step 3: Configure Cloudflare Tunnel

Add auth-service to `infra/playbooks/40_platform.yml`:

```yaml
- hostname: auth.furchert.ch
  service: http://auth-service.apps.svc.cluster.local:8080
```

Apply:
```bash
ansible-playbook infra/playbooks/40_platform.yml
```

#### Step 4: Bootstrap First Admin User

After auth-service is running, create the first admin user:

```bash
# Generate BCrypt hash
HASH=$(htpasswd -bnBC 12 "" yourpassword | tr -d ':\n')

# Insert into database
kubectl exec -n apps deploy/postgresql -- psql -U postgres -d homelabdb \
  -c "INSERT INTO users (username, email, password_hash, role, status) VALUES ('admin', 'admin@homelab.local', '${HASH}', 'ADMIN', 'ACTIVE');"
```

**Alternative:** Use `psql` locally with port-forwarding:
```bash
kubectl port-forward -n apps svc/postgresql 5432:5432
PGPASSWORD=<db-password> psql -h localhost -U <db-username> -d homelabdb
```

#### Step 5: Deploy to Kubernetes

Push to `main` branch to trigger Flux CD, or apply manually:

```bash
kubectl apply -k k8s/
```

#### Step 6: Verify Deployment

See [Post-Deployment Verification](#6-post-deployment-verification) below.

---

### Upgrading an Existing Deployment

**Flux CD (automatic):** Simply push to `main`. Nothing else needed.

**Manual update (emergency):**
```bash
# Update image tag in k8s/deployment.yaml
# Then apply
kubectl apply -f k8s/deployment.yaml
kubectl rollout status deployment/auth-service -n apps
```

---

## 6. Post-Deployment Verification

### Basic Health Checks

```bash
# Pod status
kubectl get pods -n apps -l app=auth-service

# Rollout status
kubectl rollout status deployment/auth-service -n apps

# Pod logs
kubectl logs -n apps deployment/auth-service --tail=50

# Health endpoint (via port-forward)
kubectl port-forward -n apps svc/auth-service 8080:8080
curl -s http://localhost:8080/actuator/health
```

### OIDC Endpoint Verification

```bash
# Discovery document
curl -s https://auth.furchert.ch/.well-known/openid-configuration | jq

# JWKS endpoint
curl -s https://auth.furchert.ch/oauth2/jwks | jq

# Verify issuer matches configuration
curl -s https://auth.furchert.ch/.well-known/openid-configuration | jq '.issuer'
```

**Expected output:** `"https://auth.furchert.ch"`

### Public Access Verification

1. Open `https://auth.furchert.ch/login` in a browser
2. Verify login page loads without errors
3. Attempt to log in with the bootstrap admin user

### Cluster-Internal Access Verification

```bash
# From another pod in the cluster
kubectl run -n apps curl-test --image=curlimages/curl --restart=Never --rm -it -- \
  curl -s http://auth-service.apps.svc.cluster.local:8080/actuator/health

# Or test JWKS internally
kubectl run -n apps curl-test --image=curlimages/curl --restart=Never --rm -it -- \
  curl -s http://auth-service.apps.svc.cluster.local:8080/oauth2/jwks
```

---

## 7. Health Checks & Monitoring

### Kubernetes Probes

The deployment defines:

**Liveness Probe:**
- **Endpoint:** `GET /actuator/health`
- **Port:** 8080
- **Initial Delay:** 30 seconds
- **Period:** 10 seconds
- **Failure Threshold:** 3 failures

**Readiness Probe:**
- **Endpoint:** `GET /actuator/health`
- **Port:** 8080
- **Initial Delay:** 20 seconds
- **Period:** 5 seconds
- **Failure Threshold:** 3 failures

### Available Endpoints

| Endpoint | Type | Description | Authentication |
|----------|------|-------------|----------------|
| `GET /actuator/health` | Health | Returns `{"status":"UP"}` or `{"status":"DOWN"}` | None |
| `GET /actuator/info` | Info | Service metadata (name, version, etc.) | None |

### Monitoring Recommendations

1. **Alert on:** Pod crash, readiness probe failure, high memory usage
2. **Monitor:** `/actuator/health` endpoint availability
3. **Log aggregation:** Collect pod logs via Loki/Grafana
4. **Error tracking:** Enable Sentry for error reporting (optional)

---

## 8. Runbooks & Common Operations


### Restart Service

```bash
kubectl rollout restart deployment/auth-service -n apps
kubectl rollout status deployment/auth-service -n apps
```

### View Logs

```bash
# Recent logs
kubectl logs -n apps deployment/auth-service --tail=100

# Follow logs
kubectl logs -n apps deployment/auth-service --tail=100 -f

# Previous logs (if pod crashed)
kubectl logs -n apps deployment/auth-service --previous
```

### RSA Key Rotation

When rotating RSA keys, **all existing tokens become invalid immediately**.

**Steps:**

```bash
# 1. Generate new key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 2. Update K8s Secret
kubectl delete secret homelab-auth-rsa-keys -n apps
kubectl create secret generic homelab-auth-rsa-keys -n apps \
  --from-file=private.pem=./private.pem \
  --from-file=public.pem=./public.pem

# 3. Restart service
kubectl rollout restart deployment/auth-service -n apps

# 4. Clean up
rm private.pem public.pem
```

**Side Effects:**
- All existing access tokens are immediately invalidated
- Downstream services cache JWKS by `kid` — they will pick up the new public key on their next JWKS fetch or pod restart
- Consider revoking all refresh tokens (optional)

### Add a New OIDC Client

**Step 1:** Generate client secret encoding

**Option A (simple):**
```bash
CLIENT_SECRET_ENCODED="{noop}my-new-secret"
```

**Option B (secure):**
```bash
HASH=$(htpasswd -bnBC 12 "" "my-new-secret" | tr -d ':\n')
CLIENT_SECRET_ENCODED="{bcrypt}${HASH}"
```

**Step 2:** Update K8s Secret
```bash
kubectl patch secret homelab-auth-secrets -n apps \
  --type merge \
  -p '{"stringData":{"my-new-client-secret":"'"${CLIENT_SECRET_ENCODED}"'"}}'
```

**Step 3:** Add client to `application.yaml`

```yaml
app:
  oidc:
    clients:
      - client-id: my-new-client
        client-secret: "${MY_NEW_CLIENT_SECRET}"
        redirect-uris:
          - "https://my-new-client.furchert.ch/login/oauth2/code/my-new-client"
        post-logout-redirect-uris:
          - "https://my-new-client.furchert.ch"
        scopes: [openid, profile, email]
```

**Step 4:** Reference secret in `k8s/deployment.yaml`

Add to `env` section:
```yaml
- name: MY_NEW_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: homelab-auth-secrets
      key: my-new-client-secret
```

**Step 5:** Restart service
```bash
kubectl rollout restart deployment/auth-service -n apps
kubectl rollout status deployment/auth-service -n apps
```

---

## 9. Troubleshooting Guide

### Service Fails to Start - Flyway Migration Error

**Symptoms:** Pod in CrashLoopBackOff, logs show Flyway error

**Common Causes & Solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| `database unreachable` | Wrong DB URL or credentials | Check `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` env vars. Verify PostgreSQL is running. |
| `checksum mismatch` | Existing migration file was edited | Restore original migration file or repair with `flyway repair` |
| `non-empty schema, no history table` | DB has tables but no Flyway history | Use baseline mode: `FLYWAY_BASELINE_ON_MIGRATE=true`, `FLYWAY_BASELINE_VERSION=4` |

### Service Fails to Start - RSA Key Error

**Symptoms:** Pod in CrashLoopBackOff, logs show RSA/PEM error

**Common Causes & Solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| `No such file or directory` | Keys not mounted correctly | Check volume mount path is `/etc/secrets` |
| `Invalid PEM format` | Keys are corrupted or wrong format | Regenerate keys and recreate secret |

### JWT Validation Failures in Downstream Services

**Common Causes:**
- RSA keys rotated (old key not cached) → Restart downstream services
- `app.oidc.issuer` doesn't match token → Ensure issuer is `https://auth.furchert.ch`
- Token expired → Client must refresh using refresh_token

### OIDC Login Page Not Reachable / Redirect Loop

**Common Causes:**
- `app.oidc.issuer` doesn't match hostname → Set to `https://auth.furchert.ch`
- `forward-headers-strategy` not set → Set `server.forward-headers-strategy=native`
- Multiple pod replicas → Scale to 1 pod or add session backend

### Pod Stuck in Pending or ImagePullBackOff

Check with:
```bash
kubectl describe pod -n apps <pod-name>
```

**Common causes:** Insufficient CPU/memory, nodeSelector mismatch, image not available for node architecture.

---

## 10. Security Considerations

### Secret Management

**DO:**
- Store all secrets in Kubernetes Secrets
- Use Spring Security encoding (`{noop}`, `{bcrypt}`) for client secrets
- Rotate RSA keys periodically

**DON'T:**
- Never commit secrets to Git
- Never use plaintext client secrets without encoding prefix
- Never log passwords, tokens, or secrets

### Network & Token Security

- **TLS:** All external traffic via Cloudflare Tunnel (TLS at edge)
- **Access Token:** 15 minutes expiry, RSA-2048 signed
- **Refresh Token:** 7 days expiry, stored in database
- **Sessions:** In-memory (single pod only), cookie-based with CSRF protection

---

## Configuration Reference

### Environment Variables

| Variable | Source | Required | Description |
|----------|--------|----------|-------------|
| `DB_USERNAME` | Secret `homelab-db-credentials` | Yes | PostgreSQL username |
| `DB_PASSWORD` | Secret `homelab-db-credentials` | Yes | PostgreSQL password |
| `GRAFANA_CLIENT_SECRET` | Secret `homelab-auth-secrets` | Yes | Grafana OIDC client secret |
| `HA_CLIENT_SECRET` | Secret `homelab-auth-secrets` | Yes | Home Assistant OIDC client secret |
| `DEVICE_SERVICE_CLIENT_SECRET` | Secret `homelab-auth-secrets` | Yes | device-service OIDC client secret |
| `N8N_CLIENT_SECRET` | Secret `homelab-auth-secrets` | Yes | n8n OIDC client secret |
| `LITELLM_CLIENT_SECRET` | Secret `homelab-auth-secrets` | Yes | LiteLLM OIDC client secret |
| `SENTRY_DSN` | Secret `sentry-dsn` | No | Sentry DSN for error tracking |

### Kubernetes Secrets

| Secret | Keys | Purpose |
|--------|------|---------|
| `homelab-db-credentials` | `username`, `password` | Database credentials |
| `homelab-auth-rsa-keys` | `private.pem`, `public.pem` | RSA key pair |
| `homelab-auth-secrets` | `grafana-client-secret`, `ha-client-secret`, `device-service-client-secret`, `n8n-client-secret-authservice`, `litellm-client-secret-authservice` | OIDC client secrets |
