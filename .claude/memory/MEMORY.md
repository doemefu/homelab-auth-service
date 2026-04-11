# Memory — homelab-auth-service

<!-- Newest entry at the top. Each block: id, date, decision/status, worklog link, open items. -->

- [SS7 OAuth2 AS API](feedback_ss7_oauth2_api.md) — Use http.oauth2AuthorizationServer() not static authorizationServer()
- [MockMvc query string](feedback_mockmvc_querystring.md) — MockMvc .param() doesn't set query string; use UriComponentsBuilder for GET AS endpoints
- [Testcontainers lifecycle](feedback_testcontainers_lifecycle.md) — Use @Testcontainers + @Container, never static initializer — static breaks with multiple Spring contexts
- [TokenCleanupScheduler SQL](feedback_cleanup_scheduler_sql.md) — COALESCE-to-epoch inside GREATEST matches all-NULL rows; always guard with IS NOT NULL
- [OIDC client secret prefix](feedback_oidc_secret_prefix.md) — DelegatingPasswordEncoder requires {noop}/{bcrypt} prefix; missing prefix = BCrypt mismatch = silent auth failure
- [Jackson 3 imports](feedback_jackson3_imports.md) — Project uses tools.jackson (Jackson 3), not com.fasterxml.jackson (Jackson 2)

## 2026-04-11 — PR #15 review fixes (10 Copilot + CodeQL findings)

**Decision:** Addressed all 10 open findings from PR #15 automated reviews. Key fixes: TokenCleanupScheduler SQL WHERE bug (COALESCE-to-epoch), k8s OIDC client secrets missing env vars, SENTRY_DSN optional, Jackson 3 imports, AbstractIntegrationTest @Testcontainers lifecycle, README/CONTRIBUTING doc corrections.
**Worklog:** `.claude/worklogs/20260411-211223-pr15-review-fixes-k9r2.md`
**Status:** done — pending commit + push by user
**Open:**
- User must commit changes and push to `dev` to trigger CI and mark PR comments as outdated
- Operator must create `homelab-oidc-client-secrets` Secret in namespace `apps` before deploying
- CI was failing pre-commit due to Testcontainers static initializer issue; @Testcontainers fix should resolve it

## 2026-04-09 — Fix OIDC authorize 400 in integration tests

**Decision:** MockMvc's `.param()` does not populate `request.getQueryString()` for GET requests. Spring AS reads OAuth2 params from the query string via `OAuth2EndpointUtils.getQueryParameters()`. Fixed by building authorize URL with `UriComponentsBuilder` instead of `.param()`.
**Worklog:** `.claude/worklogs/20260409-163000-oidc-authorize-400-k7m2.md`
**Status:** done — pending CI verification
**Open:**
- Push to `dev` branch and verify all 48 tests pass in CI
- Merge PR #15 once green

## 2026-04-08 — M2: OIDC IdP — implementation complete, pending CI verification

**Decision:** OIDC IdP implemented via Spring Authorization Server 7.0.4. Proprietary JWT auth API (jjwt) fully removed. Two filter chains: AS in AuthorizationServerConfig (order 1), resource server in SecurityConfig (order 2). Static clients (Grafana, Home Assistant) in application.yaml with env var secrets.
**Worklog:** `.claude/worklogs/20260408-210000-oidc-idp-impl-k4m9.md`
**Plan:** `docs/superpowers/plans/2026-04-08-oidc-idp.md`
**Spec:** `docs/superpowers/specs/2026-04-07-oidc-design.md`
**Status:** in_progress — code complete, 37/37 unit tests pass, integration tests need Docker (CI)
**Key SS7 API changes discovered:**
- `http.oauth2AuthorizationServer(...)` replaces `OAuth2AuthorizationServerConfigurer.authorizationServer()`
- `PathPatternRequestMatcher.pathPattern()` replaces `AntPathRequestMatcher`
- `OAuth2AuthorizationServerConfiguration.jwtDecoder()` lives in `config.annotation.web.configuration` package
**Open:**
- Run integration tests with Docker (CI or local Docker Desktop)
- K8s Secrets: add `GRAFANA_CLIENT_SECRET`, `HA_CLIENT_SECRET` before deploy
- Set `app.oidc.issuer` to production URL in K8s ConfigMap
- Commit and push to trigger CI

## 2026-04-06 — M1: Critical review fixes applied (40/40 unit tests green)

**Decision:** All 16 findings from critical review addressed + 3 additional reviewer findings. Key changes: SHA-256 refresh token hashing, LocalDateTime→Instant migration, kid in JWKS/JWT, AccessDeniedException handling, token invalidation on username change / password reset, service-layer role+status validation, expired token cleanup scheduler, V2 Flyway migration, K8s `:latest`→`:<SHA>`, project spec updated to Java 25/SB 4.0.5.
**Worklog:** `.claude/worklogs/20260406-120000-m1-review-fixes-q9k3.md`
**Status:** done
**Tests:** 40/40 unit tests pass (was 36). 4 new tests for role validation, token invalidation on username change/password reset.
**Docs updated:** README, OPERATIONS, CONTRIBUTING, CHANGELOG, project spec (050-iot-app-rewrite.md)
**Open:**
- Run `./mvnw verify` with Docker (Testcontainers — still blocked by local Docker socket)
- Push code + trigger CI/CD pipeline (validates integration tests on GitHub Actions)
- Create K8s Secrets before deploy
- Bootstrap first ADMIN user via psql

## 2026-04-02 — M1: Full implementation complete (36/36 unit tests green)

**Decision:** M1 homelab-auth-service fully implemented: RSA JWT (jjwt 0.12.6), user CRUD, refresh token rotation, JWKS endpoint, Flyway schema, Dockerfile (multi-arch), K8s manifests, GitHub Actions CI/CD, complete test suite.
**Worklog:** `.claude/worklogs/20260402-100000-m1-initial-impl-k7p2.md`
**Status:** done
**Key SB4/SS7 fixes documented in worklog § 6.ship:**
- Mock `JwtService` not `JwtAuthenticationFilter` in `@WebMvcTest` (final `doFilter`)
- `@Import(SecurityConfig.class)` required in `@WebMvcTest` (not auto-scanned)
- Use `SecurityMockMvcRequestPostProcessors.user(...)` not `@WithMockUser` with STATELESS sessions
**Open:**
- Run `./mvnw verify` with Docker (Testcontainers socket issue on local Mac — postponed)
- Create K8s Secrets `homelab-db-credentials` + `homelab-auth-rsa-keys` in namespace `apps`
- Bootstrap: insert first ADMIN user via psql (see README)
- GitHub repo: set `REGISTRY_TOKEN` secret for GHCR push

## 2026-04-02 — M2: Worklog template aligned to 6-phase workflow and traceability goals

**Decision:** `.claude/worklog-template.md` was rewritten to match the 6 workflow phases (`research`, `plan`, `review`, `implement`, `check implementation`, `ship`) and Java/Spring validation flow. Added required sections for summaries, findings, decision log, and lessons learned to document why decisions were made and reduce repeated errors.
**Worklog:** _not created for this template-only maintenance change_
**Status:** done
**Open:**
- Consider adding a short "when to skip TDD" rule in `CLAUDE.md` (docs/chore-only exceptions)
- Fix typo `sensefull` -> `sensible` in `CLAUDE.md`
- Verify whether `phase` enum values should be standardized (e.g., `check_implementation`) for tooling

## 2026-04-02 — M1: Project scaffolded, implementation not started

**Decision:** Spring Boot 4.0.5 / Java 25 project created with all dependencies in pom.xml. All source files are empty stubs. No Flyway migrations exist yet. No tests. No DTOs. No Dockerfile. RSA keys not yet generated.
**Worklog:** _none yet_
**Status:** ready to implement
**Open:**
- All implementation steps 1–17 from PLAN.md are pending
- RSA key pair needs to be generated (user action) and placed in `src/main/resources/keys/` (gitignored) before first run
- Test RSA keys needed in `src/test/resources/keys/`
- PostgreSQL port-forward must be active for local dev: `kubectl port-forward -n apps svc/postgres 5432:5432`
- `pom.xml` has `flyway-database-postgresql` dep — PLAN.md says it's not needed for SB 4.0, verify during implement phase
- `pom.xml` uses `spring-boot-starter-webmvc` instead of `spring-boot-starter-web` — confirm this is correct for SB 4.0
