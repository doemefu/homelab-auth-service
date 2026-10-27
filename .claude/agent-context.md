# Agent context — homelab-auth-service

Repo-specific facts for the `homelab-workflow` plugin agents; each agent reads only its own section. Service: OIDC/OAuth2 authorization server (Java 25 / Spring Boot 4.1 / Spring Security 7 / Spring Authorization Server), port 8080, package `ch.furchert.homelab.auth`.

## architect

- Contract file: `INTERFACES.md` (OIDC endpoints, REST admin API, JWKS, JWT/ID-token claims). Cross-repo specs go to `../docs/`, not inline here.
- Read first: `CLAUDE.md`, `INTERFACES.md`, `docs/PLAN.md`, and the touched code under `src/main/java/ch/furchert/homelab/auth/` (`config/`, `controller/`, `dto/`).
- A contract change must also define: OIDC/OAuth2 surface affected (token endpoint, JWKS `/oauth2/jwks`, discovery document, ID/access-token claims), Flyway migration filename + columns + constraints and which other services read that table, env vars / K8s secret keys (name and purpose, never values), role/scope per endpoint.
- Rollout order for breaking changes: this service ships first, consumers adapt after. Consumers: device-service and data-service (JWKS validation), furchert-ch (OIDC login + `client_credentials` with scope `netmon:read`), Open WebUI, n8n, LiteLLM, Grafana, Home Assistant (OIDC clients).
- Hand-back line: "`INTERFACES.md` updated — implementer can start."

## implementer

- Read first: `INTERFACES.md` (if contract-affecting), the worklog plan, `CLAUDE.md`, `.claude/rules/code-style-conventions.md`.
- Stack: Java 25, Spring Boot 4.1, Spring Security 7, Spring Authorization Server, Flyway, Lombok, Testcontainers.
- Packages under `ch.furchert.homelab.auth`: `config/`, `controller/`, `dto/`, `entity/`, `repository/`, `service/`, `security/`, `exception/`.
- Flyway: table `flyway_schema_history_auth` (`spring.flyway.table`), migrations `V{n}__{description}.sql`, `spring.jpa.hibernate.ddl-auto=validate` (never `update`/`create`).
- Never hardcode credentials, RSA keys or client secrets: K8s `secretKeyRef` / env vars only. Test keys live in `src/test/resources/keys/` (tracked, not real credentials); `src/main/resources/keys/` is gitignored local-dev only.
- Spring Boot 4.1 gotchas: Flyway via `spring-boot-starter-flyway`; Jackson 3 (`tools.jackson` group id); `@SpringBootTest` needs explicit `@AutoConfigureMockMvc` for MockMvc.
- Tests: Mockito + MockMvc for controllers; persistence tests use Testcontainers `PostgreSQLContainer("postgres:17-alpine")`. Passwords: BCrypt default strength. Roles `USER`, `ADMIN` as VARCHAR on `users`.
- Ready-to-deploy changes that add a secret, env var or migration: tell the devops agent after reviewer approval.

## reviewer

- Contract: verify against `INTERFACES.md` exactly (ID-token claims, UserInfo response, device client-credentials claims, REST shapes, every field and type).
- Security: OIDC/JWT endpoints enforced in `SecurityConfig` / authorization-server filter chain, no stray `permitAll()`; CSRF and `/error` handling match the documented posture; RSA keys loaded only from mounted secret/env (`homelab-auth-rsa-keys`), never committed or logged.
- Correctness: Flyway only, table `flyway_schema_history_auth`, `ddl-auto=validate`; JWKS (`/oauth2/jwks`) shape unchanged or reflected in `INTERFACES.md` (device-service, data-service, furchert-ch validate against it); client registration changes reflected in `INTERFACES.md` and `DEPLOYMENT.md`.
- Architecture: no business logic in controllers; inter-service URLs via env vars; Dockerfile uses pinned `eclipse-temurin` base images (`25-jdk-alpine` build, `25-jre-alpine` runtime) and does not run as root; Spring Boot pinned to an exact patch.
- Tests: MockMvc for controllers, Testcontainers `PostgreSQLContainer` for DB integration (no mocked Postgres).
- Repo review rules: never log secrets/tokens/credentials; minimal diffs; pinned dependency versions; unit + integration tests required.
- Bot review: Copilot auto-reviews this repo (verified PR #78); CodeRabbit unverified. If Copilot quota is exhausted, comment `@coderabbitai review`; if no bot reviews, fall back to reviewer + `/code-review`, disclosed in a PR comment. Wait for the bot review and answer every comment before merging.

## documenter

- Maintain: `docs/PLAN.md` (mark phases complete, update status table, record deviations; never delete future phases), `CLAUDE.md` (build commands, architecture section), `README.md`.
- `README.md` must contain: what the service does (2-3 sentences); key endpoints (method, path, auth, description); env vars read (name + description); local build/run; running locally against a port-forwarded cluster DB (`kubectl -n apps port-forward svc/postgresql 5432:5432`).
- Doc ownership table lives in `.claude/rules/documentation-files.md` content: README (landing/index), OVERVIEW (service, features, URL/API summary), INTERFACES (integrators), DEPLOYMENT (K8s, secrets, ingress, troubleshooting), CONTRIBUTING (local dev, tests, PR process), CHANGELOG (user-affecting changes), `docs/INDEX.md`, `docs/DEVELOPMENT.md`.
- Docs are written in parallel with the code change, in English.

## devops

- Image: `ghcr.io/doemefu/homelab-auth-service`; CI builds multi-arch. Flux image automation picks up the new `main-YYYYMMDDTHHmmss` tag and updates `k8s/deployment.yaml`; no manual `kubectl apply`.
- Secrets `homelab-db-credentials`, `homelab-auth-rsa-keys`, `homelab-auth-secrets` are provisioned by the `infrastructure` repo's `infra/playbooks/59_app_services.yml` via SOPS. Never provision or edit them here.
- Namespace `apps`, deployment/app label `auth-service`. Checks: `gh run list -R doemefu/homelab-auth-service --limit 5`; `kubectl -n apps rollout status deployment/auth-service`; `kubectl -n apps get pods -l app=auth-service`; `kubectl -n apps logs deployment/auth-service --tail=50`.
- New env var or secret key: confirm `DEPLOYMENT.md` documents it and tell the user the infrastructure playbook needs the entry (do not edit that repo). New Flyway migration runs automatically on pod start; no manual step.
- Do not touch: `k8s/` image tag (Flux/CI owns it), RSA keys, SOPS files, the `infrastructure` repo.
- K8s manifest expectations: resource limits, liveness probe, pinned image tag, `secretKeyRef` for secrets, namespace `apps`.

## plan-reviewer

- Plans use the 8-section structure (`plan-structure.md` in the plugin `workflow` skill).
- Secrets: tests use only `src/test/resources/keys/` keys; no plaintext RSA keys/credentials in code, properties or fixtures.
- Version pinning: no ranges in `pom.xml`; Spring Boot pinned to an exact patch.
- DB migrations: Flyway only (`V{n}__{description}.sql`), idempotent against an already-migrated DB, never `ddl-auto=create/update`.
- OIDC/JWT/security: does the plan alter claims, scopes, grant types or endpoint paths documented in `INTERFACES.md`, and update it in the same plan? All authed endpoints enforced in `SecurityConfig`/`AuthorizationServerConfig` (no stray `permitAll()`)? Role checks at the right layer?
- Tests: Testcontainers for DB integration; unit test per new public service method; MockMvc per endpoint covering success, validation error, unauthorized, not found.
- K8s (only if `k8s/` touched): resource limits, liveness probe, pinned image tag, `secretKeyRef`, namespace `apps`.
- Architecture: business logic in service layer; works after a pod restart (no required in-memory state); does it break a consumer (device-service, data-service, furchert-ch, Open WebUI/n8n/LiteLLM) outside the plan's scope? New dependency explicitly approved?

## doc-auditor

- Context: OIDC/OAuth2 server deployed to K3s namespace `apps` via Cloudflare Tunnel; Secrets provisioned by the `infrastructure` repo's `infra/playbooks/59_app_services.yml`. Consumers: device-service, data-service, furchert-ch, Grafana, Home Assistant, n8n, LiteLLM, Open WebUI.
- Read in full: `README.md`, `OVERVIEW.md`, `INTERFACES.md`, `DEPLOYMENT.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/INDEX.md`, `docs/DEVELOPMENT.md`.
- `README.md`: milestone/status table current; new prerequisite listed.
- `OVERVIEW.md`: service description, feature list, API summary accurate.
- `INTERFACES.md`: new/changed OIDC endpoint, claim, scope, grant type or REST response shape documented.
- `DEPLOYMENT.md`: new env var or K8s Secret key (e.g. in `homelab-auth-secrets`, via the infrastructure playbook); probe timing or resource limits; new OIDC client listed in the Secrets table and covered by "Configure a New OIDC Client".
- `CONTRIBUTING.md`: new local-dev prerequisite, test command or Flyway convention.
- `CHANGELOG.md`: user-visible change recorded. `docs/INDEX.md` / `docs/DEVELOPMENT.md`: new supplementary material indexed.
