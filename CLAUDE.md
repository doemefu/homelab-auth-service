# CLAUDE.md — homelab-auth-service

> In-progress worklogs are listed at session start by the `homelab-workflow` plugin; start work with `/homelab-workflow:start-task`. Durable facts go to auto memory. `.claude/worklogs/` is gitignored (local-only); cross-check `git log` and GitHub when it looks stale.

## Service Overview

JWT authentication service for the doemefu homelab IoT ecosystem. Issues OAuth2/OIDC access, ID, and refresh tokens (RSA-signed, via Spring Authorization Server), manages users, and exposes a JWKS endpoint for other services to validate tokens.

**Port:** 8080
**Package:** `ch.furchert.homelab.auth`
**Database:** PostgreSQL — `users`, `oauth2_authorization`, `oauth2_authorization_consent`, `oauth2_registered_client`, `login_event_outbox` tables (Flyway migrations in `src/main/resources/db/migration/`)

## Architecture Context

device-service and furchert-ch consume tokens issued by this service — device-service validates JWTs via the JWKS endpoint (`/oauth2/jwks`), furchert-ch authenticates its OIDC-gated `/dashboard` via full OIDC login against this IdP. Open WebUI, n8n, and LiteLLM are additionally registered as OIDC clients. data-service validates JWTs via the JWKS endpoint like device-service; furchert-ch fetches `client_credentials` tokens with scope `netmon:read` for it (V6); the `data-service` client (scope `login-events:read`) pulls login events. This service makes no runtime calls to other services — it is purely a producer of tokens and identity.

**Full architecture spec:** `../docs/052-architecture-target.md`
**mcp-hub:** this service is its authorization server — pre-registered client `claude-mcp-hub`, audience-bound tokens (`../docs/adr/0003-mcp-hub-authorization.md`, contract `../docs/080-mcp-hub.md` §4). Changes to that client or the token shape are cross-repo contract changes.
**data-service:** pulls `/api/v1/login-events` with client `data-service` (scope `login-events:read`); contract in `../docs/060-network-monitoring.md`.
**Implementation plan:** `docs/PLAN.md`

## Non-Negotiables

- Do **not** touch RSA key files, secrets, or credentials
- Do **not** use `latest` for any dependency version — all versions pinned
- Do **not** use `ddl-auto=update` or `ddl-auto=create` — Flyway only
- Do **not** log passwords, tokens, or secrets in any form
- Do **not** introduce new dependencies without explicit user approval
- Commit, push and open PRs on feature branches without asking. Merging PRs is always the user's. Rolling out changes the user has already merged needs no extra go; force-pushes, playbook runs and other cluster mutations need an explicit go. SOPS files are never read or edited by Claude — the user edits them.
- Before any merge, wait for the Copilot review and fix or answer every comment (`/homelab-workflow:review-gate`).
- All comments and documentation in **English**
- Minimize diff size: no drive-by refactors

## Tech Stack (pinned)

| Component | Version |
|-----------|---------|
| Java | 25 |
| Spring Boot | 4.1.2 |
| Spring Authorization Server | via `spring-boot-starter-oauth2-authorization-server` (Spring Boot 4.1 BOM-managed) |
| springdoc-openapi | 3.1.1 |
| Testcontainers BOM | 2.0.5 (project-managed via dependencyManagement import) |
| Base image | `eclipse-temurin:25-jre-alpine` (build stage: `eclipse-temurin:25-jdk-alpine`) |

## Spring Boot 4.1 Notes

- Flyway via `spring-boot-starter-flyway` (no separate dialect dep)
- Jackson 3 (`tools.jackson` group ID)
- `@SpringBootTest` needs explicit `@AutoConfigureMockMvc` for MockMvc
- Spring Security 7.0

## Agent Team

Agents come from the `homelab-workflow` plugin: `homelab-workflow:<role>` (`architect`, `implementer`, `reviewer`, `documenter`, `devops`, `plan-reviewer`, `doc-auditor`). Repo specifics (contract file `INTERFACES.md`, secrets, consumers, doc targets) live in `.claude/agent-context.md`, one section per role. There are no repo-only agents.

## Service-Specific Conventions

- Flyway for all DB migrations (`spring.flyway.table=flyway_schema_history_auth`)
- `spring.jpa.hibernate.ddl-auto=validate`
- Package structure: `config/`, `controller/`, `dto/`, `entity/`, `repository/`, `service/`, `security/`, `exception/`
- BCrypt for password hashing (default strength)
- Roles: `USER`, `ADMIN` — stored as VARCHAR on users table

## Testing

- Unit tests: Mockito, MockMvc for controllers
- Integration tests: Testcontainers with `PostgreSQLContainer("postgres:17-alpine")`
- Test RSA keys: `src/test/resources/keys/`
- Tests are required for every feature

---

## Commands

```bash
./mvnw clean package              # Build
./mvnw clean package -DskipTests  # Build without tests
./mvnw spring-boot:run            # Run locally (port-forward cluster DB first)
./mvnw test                       # All tests
./mvnw test -Dtest=ClassName      # Single test class
./mvnw verify                     # Full build + tests
docker build -t auth-service .    # Build image

# Cluster access (local dev)
kubectl port-forward -n apps svc/postgresql 5432:5432  # service is `postgresql`, not `postgres`
kubectl get nodes -o wide
kubectl get pods -n apps
```

## Process & Conventions

Workflow, worklog format, plan structure, review gate and the GitHub Project #5 board come from the plugin skills:
`/homelab-workflow:start-task`, `workflow`, `review-gate`, `project-board`, `cross-repo`.

Repo rules in `.claude/rules/` (path-scoped, auto-loaded by Claude Code):

| Rule file | Covers |
|-----------|--------|
| `code-style-conventions.md` | Java/Spring Boot, Lombok, Flyway, secrets (Java, SQL, yaml, pom, k8s, Dockerfile) |
| `documentation-files.md` | README, OVERVIEW, INTERFACES, DEPLOYMENT, CONTRIBUTING, CHANGELOG, docs/INDEX, docs/DEVELOPMENT (`**/*.md`) |
