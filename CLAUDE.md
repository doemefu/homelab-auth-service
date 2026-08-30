# CLAUDE.md — homelab-auth-service

> **Session start:** Read `.claude/memory/MEMORY.md` completely. The topmost entry shows the current state. If there is an entry with `status: in_progress`, read the linked worklog and ask the user: *"I see we were interrupted at [SLUG]. Continue?"* — before doing anything else.

> **After each completed change:** Insert a new block **at the top** of `.claude/memory/MEMORY.md`. The file grows top-down — newest entries always visible first.

> `.claude/memory/` and `.claude/worklogs/` are gitignored — local-only; cross-check `git log` and GitHub when they look stale.

## Service Overview

JWT authentication service for the doemefu homelab IoT ecosystem. Issues OAuth2/OIDC access, ID, and refresh tokens (RSA-signed, via Spring Authorization Server), manages users, and exposes a JWKS endpoint for other services to validate tokens.

**Port:** 8080
**Package:** `ch.furchert.homelab.auth`
**Database:** PostgreSQL — `users`, `refresh_tokens` tables

## Architecture Context

device-service and furchert-ch consume tokens issued by this service — device-service validates JWTs via the JWKS endpoint (`/oauth2/jwks`), furchert-ch authenticates its OIDC-gated `/dashboard` via full OIDC login against this IdP. Open WebUI, n8n, and LiteLLM are additionally registered as OIDC clients. data-service is planned to integrate the same way once deployed. This service makes no runtime calls to other services — it is purely a producer of tokens and identity.

**Full architecture spec:** `../docs/052-architecture-target.md`
**Implementation plan:** `docs/PLAN.md`

## Non-Negotiables

- Do **not** touch RSA key files, secrets, or credentials
- Do **not** use `latest` for any dependency version — all versions pinned
- Do **not** use `ddl-auto=update` or `ddl-auto=create` — Flyway only
- Do **not** log passwords, tokens, or secrets in any form
- Do **not** introduce new dependencies without explicit user approval
- Commit, push and open PRs on feature branches without asking (standing permission, 2026-08-28). Merging, force-pushes, playbook runs, cluster mutations and anything touching SOPS/secrets need an explicit go for that task.
- Before any merge, wait for the Copilot review and fix or answer every comment (see `.claude/rules/workflow.md` Phase 5).
- All comments and documentation in **English**
- Minimize diff size: no drive-by refactors

## Tech Stack (pinned)

| Component | Version |
|-----------|---------|
| Java | 25 |
| Spring Boot | 4.1.1 |
| Spring Authorization Server | via `spring-boot-starter-oauth2-authorization-server` (Spring Boot 4.1 BOM-managed) |
| springdoc-openapi | 3.1.0 |
| Testcontainers BOM | 2.0.5 (project-managed via dependencyManagement import) |
| Base image | `eclipse-temurin:25-jre-alpine` (build stage: `eclipse-temurin:25-jdk-alpine`) |

## Spring Boot 4.1 Notes

- Flyway via `spring-boot-starter-flyway` (no separate dialect dep)
- Jackson 3 (`tools.jackson` group ID)
- `@SpringBootTest` needs explicit `@AutoConfigureMockMvc` for MockMvc
- Spring Security 7.0

## Agent Team

Seven project-level agents in `.claude/agents/` handle bigger implementations.

| Agent | Model | Role |
|-------|-------|------|
| `architect` | opus | Writes contract specs for changes that affect other services — into `INTERFACES.md`, or `../docs/` for cross-repo specs — before implementation begins |
| `implementer` | sonnet | Implements the plan: Java/Spring Boot code, Flyway migrations, tests |
| `reviewer` | opus | Reviews implemented code for security and contract compliance against `INTERFACES.md` |
| `documenter` | sonnet | Keeps `docs/PLAN.md`, `CLAUDE.md`, and `README.md` accurate as work lands |
| `devops` | sonnet | Verifies K8s manifests and cluster health after deploys (read-only `kubectl`) |
| `plan-reviewer` | (inherit) | Phase 3 review — defects and architectural soundness of the plan |
| `doc-auditor` | (inherit) | Phase 6 doc audit — checks README/DEPLOYMENT/CONTRIBUTING/CHANGELOG for gaps |

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

## Process & Conventions

Detailed process rules are in `.claude/rules/` (auto-loaded by Claude Code):

| Rule file | Covers |
|-----------|--------|
| `workflow.md` | 6-phase milestone workflow (includes plan approval checklist) |
| `worklog-conventions.md` | Worklog location, naming, header, structure |
| `plan-structure.md` | 8-section plan template |
| `commands.md` | Build, test, cluster access commands |
| `code-style-conventions.md` | Java/Spring Boot, Lombok, Flyway, secrets |
| `review-guidelines.md` | Security, diffs, version pinning, tests |
| `documentation-files.md` | README, OVERVIEW, INTERFACES, DEPLOYMENT, CONTRIBUTING, CHANGELOG, docs/INDEX, docs/DEVELOPMENT |
| `github-project.md` | GitHub Project #5 status transitions |
