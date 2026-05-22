# Memory — homelab-auth-service

<!-- Newest entry at the top. Each block: id, date, decision/status, worklog link, open items. -->

- [Method security required](feedback_method_security_required.md) — @PreAuthorize is silently ignored without @EnableMethodSecurity; AuthorizationDeniedException needs explicit 403 mapping
- [SS7 JWT scope shape](feedback_ss7_jwt_scope_shape.md) — JWT payload encodes `scope` as array, token response as string
- [SS7 OAuth2 AS API](feedback_ss7_oauth2_api.md) — Use http.oauth2AuthorizationServer() not static authorizationServer()
- [MockMvc query string](feedback_mockmvc_querystring.md) — MockMvc .param() doesn't set query string; use UriComponentsBuilder for GET AS endpoints
- [Testcontainers lifecycle](feedback_testcontainers_lifecycle.md) — Use @Testcontainers + @Container, never static initializer — static breaks with multiple Spring contexts
- [TokenCleanupScheduler SQL](feedback_cleanup_scheduler_sql.md) — COALESCE-to-epoch inside GREATEST matches all-NULL rows; always guard with IS NOT NULL
- [OIDC client secret prefix](feedback_oidc_secret_prefix.md) — DelegatingPasswordEncoder requires {noop}/{bcrypt} prefix; missing prefix = BCrypt mismatch = silent auth failure
- [Jackson 3 imports](feedback_jackson3_imports.md) — Project uses tools.jackson (Jackson 3), not com.fasterxml.jackson (Jackson 2)

## 2026-05-22 — Revert DeviceClientServiceTest matcher change

**Decision:** Reverted `DeviceClientServiceTest#get_unknownClient_throws404` to keep `@SuppressWarnings("unchecked")` and raw `RowMapper.class` matcher at user request due local test failures after typed-matcher refactor.
**Worklog:** _none_
**Status:** done — pending commit by user
**Open:**
- User can rerun test suite on their environment to confirm stability

## 2026-05-13 — IoT Device OAuth2 Clients shipped (JDBC repo + admin API)

**Decision:** Implemented `docs/SPEC-iot-device-clients.md`. Switched Spring AS `RegisteredClientRepository` from in-memory to JDBC via Flyway V5 (`oauth2_registered_client` + `client_kind` extension column). Added `StaticClientSeeder` (idempotent YAML→DB bootstrap), `/api/v1/clients` admin CRUD (gated by `hasRole('ADMIN') or hasAuthority('SCOPE_clients:admin')`), `device_id` JWT claim for `client_credentials` tokens with `client_kind='device'`, `ClientKindLookup` per-JVM cache. `device-service` client is now multi-grant (auth_code + refresh_token + client_credentials) with `clients:admin` scope. `@EnableMethodSecurity` enabled.
**Worklog:** `.claude/worklogs/20260513-113126-iot-device-clients-x7p3.md`
**Plan:** `~/.claude/plans/implement-docs-spec-iot-device-clients-m-cozy-sedgewick.md`
**Spec:** `docs/SPEC-iot-device-clients.md`
**Status:** done — 88/88 tests pass (`./mvnw verify`), pending commit by user
**Plan-reviewer findings:** 3 blockers (F1 secret double-encode, F2 method-security off, F3 converter NPE) + 1 high-impact warning (F4 SSO-client delete data loss) all fixed and verified by dedicated tests before any code was committed.
**Open:**
- User must commit + push (workflow rule: never auto-commit)
- Operator runbook change: SSO client-secret rotation now requires `psql UPDATE oauth2_registered_client SET client_secret = ...` (YAML env var alone is no-op after first boot) — documented in OPERATIONS.md
- Operator runbook change: manual `client_kind` edits via psql require `kubectl rollout restart` (cache)
- HA follow-up: replace `ClientKindLookup` in-memory cache if auth-service ever scales > 1 replica
- GitHub project status: read:project scope was missing during session — move item to **Done** manually
- Mosquitto JWT plugin config to consume `device_id` claim lives in `infrastructure/053-mqtt-device-authentication.md` (out of scope here)

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
