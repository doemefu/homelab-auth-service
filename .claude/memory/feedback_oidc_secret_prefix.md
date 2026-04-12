---
name: OIDC client secret {id} prefix requirement
description: OIDC client secrets configured via env var must include Spring Security DelegatingPasswordEncoder {id} prefix; missing prefix causes silent BCrypt mismatch at /oauth2/token
type: feedback
---

All OIDC client secrets passed via environment variables (e.g. `GRAFANA_CLIENT_SECRET`, `HA_CLIENT_SECRET`) must include the Spring Security `{id}` encoder prefix.

**Why:** `SecurityConfig` creates a `DelegatingPasswordEncoder` which uses the `{id}` prefix to select the encoder. If the prefix is absent, the encoder falls back to BCrypt matching, which fails for plain-text secrets. The `/oauth2/token` endpoint returns 401 with no useful error message, making this very hard to debug.

**How to apply:**
- Local dev: `export GRAFANA_CLIENT_SECRET="{noop}local-dev-secret"`
- Production K8s: use `{bcrypt}$2a$12$...` hash, created with `htpasswd -bnBC 12 "" <secret>`
- Test fixtures in `AbstractIntegrationTest`: already correctly use `{noop}test-secret`

In `application.yaml`, the `client-secret` value is read directly from the env var — Spring does NOT hash it automatically.
