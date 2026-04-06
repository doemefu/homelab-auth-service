# CLAUDE.md — homelab-auth-service

> **Session start:** Read `.claude/memory/MEMORY.md` completely. The topmost entry shows the current state. If there is an entry with `status: in_progress`, read the linked worklog and ask the user: *"I see we were interrupted at [SLUG]. Continue?"* — before doing anything else.

> **After each completed change:** Insert a new block **at the top** of `.claude/memory/MEMORY.md`. The file grows top-down — newest entries always visible first.

## Service Overview

JWT authentication service for the doemefu homelab IoT ecosystem. Issues access/refresh tokens (jjwt + RSA), manages users, and exposes a JWKS endpoint for other services to validate tokens.

**Port:** 8080
**Package:** `ch.furchert.homelab.auth`
**Database:** PostgreSQL — `users`, `refresh_tokens` tables

## Architecture Context

This is 1 of 3 microservices. The other two (device-service, data-service) validate JWTs by fetching the RSA public key from this service's `/auth/jwks` endpoint. This service is fully self-contained — no runtime calls to other services.

**Full architecture spec:** `../../docs/052-architecture-target.md`
**Implementation plan:** `PLAN.md`

## Non-Negotiables

- Do **not** touch RSA key files, secrets, or credentials
- Do **not** use `latest` for any dependency version — all versions pinned
- Do **not** use `ddl-auto=update` or `ddl-auto=create` — Flyway only
- Do **not** log passwords, tokens, or secrets in any form
- Do **not** introduce new dependencies without explicit user approval
- Do **not** commit things. Provide a commit message and wait for the user.
- All comments and documentation in **English**
- Minimize diff size: no drive-by refactors

## Tech Stack (pinned)

| Component | Version |
|-----------|---------|
| Java | 25 |
| Spring Boot | 4.0.5 |
| jjwt | 0.12.6 |
| springdoc-openapi | 2.7.0 |
| Testcontainers BOM | 1.20.4 |

## Spring Boot 4.0 Notes

- Flyway via `spring-boot-starter-flyway` (no separate dialect dep)
- Jackson 3 (`tools.jackson` group ID)
- `@SpringBootTest` needs explicit `@AutoConfigureMockMvc` for MockMvc
- Spring Security 7.0

## Agent Team

Five project-level agents in `.claude/agents/` handle bigger implementations.

| Agent | Model | Role |
|-------|-------|------|
| `architect` | opus | Writes `CONTRACTS.md` — exact API/DB/MQTT specs before any service is built |
| `implementer` | sonnet | Builds services in order based on `CONTRACTS.md` |
| `reviewer` | opus | Reviews each service for security and contract compliance |
| `documenter` | sonnet | Keeps docs and per-service READMEs accurate |
| `devops` | sonnet | Handles K8s manifests, verifies deployment |

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
| `documentation-files.md` | README, OPERATIONS, CONTRIBUTING, DEPLOYMENT, CHANGELOG |
