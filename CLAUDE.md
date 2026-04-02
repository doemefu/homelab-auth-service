# CLAUDE.md — homelab-auth-service

> **Session start:** Read `.claude/memory/MEMORY.md` completely. The topmost entry shows the current state. If there is an entry with `status: in_progress`, read the linked worklog and ask the user: *"I see we were interrupted at [SLUG]. Continue?"* — before doing anything else.

> **After each completed change:** Insert a new block **at the top** of `.claude/memory/MEMORY.md` (format: see file). The file grows top-down — newest entries always visible first.

> **Never commit anything:** Come up with a sensefull commit message and tell the user to commit now.

## 1 Service Overview
JWT authentication service for the doemefu homelab IoT ecosystem. Issues access/refresh tokens (jjwt + RSA), manages users, and exposes a JWKS endpoint for other services to validate tokens.

**Port:** 8080
**Package:** `ch.furchert.homelab.auth`
**Database:** PostgreSQL — `users`, `refresh_tokens` tables

### Tech Stack (pinned)
| Component | Version |
|-----------|---------|
| Java | 25 |
| Spring Boot | 4.0.5 |
| jjwt | 0.12.6 |
| springdoc-openapi | 2.7.0 |
| Testcontainers BOM | 1.20.4 |

### Spring Boot 4.0 Notes
- Flyway via `spring-boot-starter-flyway` (no separate dialect dep)
- Jackson 3 (`tools.jackson` group ID)
- `@SpringBootTest` needs explicit `@AutoConfigureMockMvc` for MockMvc
- Spring Security 7.0

## 2 Architecture Context
This is 1 of 3 microservices. The other two (device-service, data-service) validate JWTs by fetching the RSA public key from this service's `/auth/jwks` endpoint. This service is fully self-contained — no runtime calls to other services.

**Full architecture spec:** `../../docs/052-architecture-target.md`
**Implementation plan:** `PLAN.md`

## 3 Non-Negotiables
- Do **not** touch RSA key files, secrets, or credentials
- Do **not** use `latest` for any dependency version — all versions pinned
- Do **not** use `ddl-auto=update` or `ddl-auto=create` — Flyway only
- Do **not** log passwords, tokens, or secrets in any form
- Do **not** introduce new dependencies without explicit user approval
- All comments and documentation in **English**
- Minimize diff size: no drive-by refactors

---

## 4 Required Workflow for Every Milestone (MUST FOLLOW)
For every user request that results in a code change, follow this 6-phase workflow and document it in a single worklog Markdown file (see "Worklog per change"). For each step, invoke the relevant superpowers skill. Pivot back to an earlier phase if things dont work out.

### Phase 1 — research
High-level goal: understand what we're doing, why, and find all relevant code.
- Identify open questions and assumptions; if something is unclear, go one step back or ask the user.
- Inspect the local codebase: search with `rg`, check `git log`, check existing patterns.
- Invoke the superpowers brainstorming skill.
- If it seems to be a big change invoke the agent team as mentioned in ## Agent Team

### Phase 2 — plan
Produce a concrete plan with alternatives and specific file changes.
- Use the Markdown plan structure from `.claude/worklog-template.md` (section 2. plan).
- Include: goal, all options considered (chosen + rejected with reasons), files to change, step-by-step edits, tests, validation commands, risks & mitigations.
- Invoke the superpowers writing-plans skill.

After writing the plan markdown, Claude MUST:
1. Display a summary of it
2. Present a **checklist for user approval**:
    - [ ] Goal is clear and achievable
    - [ ] All options are realistic
    - [ ] No missing dependencies or risks
    - [ ] Implementation steps are concrete
    - [ ] Tests are defined

3. Wait for user input:
    - "✅ Approved, proceed to Phase 3"
    - "🔄 Revise [section name]"
    - "❌ Reject, start over"

4. Only proceed to Phase 3 after explicit approval
 
### Phase 3 — review
Review the plan for defects (secret exposure, missing handlers, version pinning).
- Invoke the plan-reviewer subagent from .claude/agents/plan-reviewer.md (Sonnet model)
- Apply findings directly by updating the plan in the worklog.
- Output (a) the updated plan and (b) a concise findings table: what was found and what changed.
- use context7 to check for the latest documentation where relevant

### Phase 4 — implement
Implement the plan:
- Invoke superpower skills subagent-driven-development and/or executing-plans
- For test driven implementation invoke superpower skill test-driven-development
- use context7 to check for the latest documentation if things are unclear
- Run lint/check commands from the plan and capture results in the worklog.

### Phase 5 -- Check implementation
Reviews against plan, reports issues by severity. Critical issues block progress.
- Invoke superpowers requesting-code-review Skill

### Phase 6 — ship
- Run integration checks if possible (e.g., deploy to cluster, verify via kubectl).
- Invoke the doc-auditor subagent from .claude/agents/plan-reviewer.md (Sonnet model) to check whether OPERATIONS.md, CONTRIBUTING.md, or README.md need updates. Implement all required changes it identifies.
- Provide final summary: what changed, how verified, follow-ups.
- **Required: Insert a new block at the top of `.claude/memory/MEMORY.md`** — decision, worklog link, open items.

If anything becomes unclear in any phase, go one step back or ask the user.

## 5 Agent Team
Five project-level agents in `.claude/agents/` handle bigger implementations. Invoke when it makes sense and check the worklog for the full implementation plan.

| Agent | Model | Role |
|-------|-------|------|
| `architect` | opus | Writes `CONTRACTS.md` — exact API/DB/MQTT specs before any service is built |
| `implementer` | sonnet | Builds services in order based on `CONTRACTS.md` |
| `reviewer` | opus | Reviews each service for security and contract compliance |
| `documenter` | sonnet | Keeps docs and per-service READMEs accurate |
| `devops` | sonnet | Handles K8s manifests, verifies deployment |

---

## 6 Worklog per Change
For each change, create ONE worklog Markdown file and append phase results sequentially.
Full template with inline guidance: `.claude/worklog-template.md`
Copy it as the starting point for every new worklog. The template covers all six phases with prompts for what to write in each section. Headers are auto-generated; manually edit updated_at after major progress.

### Location
`.claude/worklogs/`

### Filename convention
`YYYYMMDD-HHMMSS-<slug>-<rand4>.md`
Example: `.claude/worklogs/20260310-142000-longhorn-prereqs-b3x1.md`

### Worklog header (MUST be at the very top)
```yaml
---
id: "YYYYMMDD-HHMMSS-<slug>-<rand4>"
title: "<short human title>"
phase: "research|plan|review|implement|ship|done"
status: "in_progress|blocked|done"
created_at: "YYYY-MM-DDTHH:MM:SS+01:00"
updated_at: "YYYY-MM-DDTHH:MM:SS+01:00"
---
```

### Worklog structure (read & append-only, phases in order)
- `## 1. research`
- `## 2. plan` (Markdown plan — see template)
- `## 3. review` (updated plan + findings table)
- `## 4. implement` (summary, commands, results)
- `## 5. check implementation` (test results, verification against plan)
- `## 6. ship` (final verification, release notes if needed)

Record every executed command and its outcome (pass/fail + key output).

---

## 7 Plan Structure
The plan lives in `## 2. plan` of the worklog. Use the template at `.claude/worklog-template.md`.

Required sections (in order):

1. **Goal** — one sentence: what must be true when done
2. **Context** — summary, assumptions (with confidence), open questions (blocker / non-blocker)
3. **Options considered** — ALL options including rejected ones; for each: what it does, pros, cons, and if rejected: why
4. **Changes** — per change: files affected + concrete steps
5. **Tests** — lint, unit tests, integration tests
6. **Validation** — the command that proves the goal is met
7. **Risks** — likelihood, impact, mitigation
8. **Ship notes** — docs to update, user actions required, follow-ups

---

## 8 Repository Commands

### Java Spring
```bash
./mvnw clean package          # Build
./mvnw spring-boot:run        # Run locally (port-forward cluster DB first)
./mvnw test                   # Run all tests
./mvnw test -Dtest=ClassName  # Run single test class
./mvnw verify                 # Full build + tests
```

### Local Development
Connect to cluster infrastructure via port-forward:
```bash
kubectl port-forward -n apps svc/postgres 5432:5432

# Check cluster status
kubectl get nodes -o wide
kubectl get pods -n apps
```

## 9 Conventions

### Code
- Standard Spring Boot conventions
- Lombok for boilerplate reduction
- Flyway for all DB migrations (`spring.flyway.table=flyway_schema_history_auth`)
- `spring.jpa.hibernate.ddl-auto=validate`
- Package structure: `config/`, `controller/`, `dto/`, `entity/`, `repository/`, `service/`, `security/`, `exception/`
- BCrypt for password hashing (default strength)
- Roles: `USER`, `ADMIN` — stored as VARCHAR on users table

### Secrets
- Plaintext secrets in git: **forbidden**
- Encrypt via SOPS + age before finishing: `sops -e -i <file>`
- age key lives **outside** the repo


## 10 Testing
- Unit tests: Mockito, MockMvc for controllers
- Integration tests: Testcontainers with `PostgreSQLContainer("postgres:17-alpine")`
- Test RSA keys: `src/test/resources/keys/`
- Tests are required for every feature

## 11 Review Guidelines
- Never log secrets, tokens, or credentials in any form
- Keep diffs minimal; no unrelated refactors
- All dependency versions must be pinned (no `latest`, no version ranges)
- Tests are required for every service (unit + integration)

---

## 12 Documentation Files — Purpose & Owner
This repo maintains documentation files. Each has a distinct audience and scope.

| File              | Audience | Covers |
|-------------------|----------|--------|
| `README.md`       | Everyone | Project overview, architecture, quick start, service links |
| `OPERATIONS.md`   | Operators | Runbooks, upgrade procedures, backup/restore, troubleshooting |
| `CONTRIBUTING.md` | Contributors | Local dev setup (port-forward), testing, PR process |
| `DEPLOYMENT.md`   | App developers | Deploying apps to the cluster: namespaces, ingress, storage, secrets |
| `CHANGELOG.md`   | App users | Describes changes to prior versions the user is affected by |

**Rule:** Docs are written in parallel with the code change, not after.