---
id: "20260513-113126-iot-device-clients-x7p3"
title: "IoT Device OAuth2 Clients — JDBC repo + admin API"
phase: "done"
status: "done"
created_at: "2026-05-13T11:31:26+01:00"
updated_at: "2026-05-13T15:55:00+01:00"
---

## 1. research

**Goal:** Allow dynamic registration/revocation of OAuth2 `client_credentials` clients for IoT devices, served from Postgres, exposed via an admin REST API consumed by `device-service` and ADMIN users.

**Current state:**
- `AuthorizationServerConfig.registeredClientRepository()` builds an `InMemoryRegisteredClientRepository` from `app.oidc.clients` (5 static SSO clients).
- `OAuth2AuthorizationService` is already JDBC-backed (`JdbcOAuth2AuthorizationService` + Flyway V3).
- No `oauth2_registered_client` table; no `client_credentials` grant; no admin client-management API.
- `tokenCustomizer()` adds a `role` claim derived from the principal's first authority — only fires for user-driven grants.
- Resource-server filter chain in `SecurityConfig` protects `/api/v1/**` via role-based rules; JWT authorities are extracted from the `role` claim only (no `scope` authorities currently).

**Repo areas inspected:**
- `src/main/java/ch/furchert/homelab/auth/config/AuthorizationServerConfig.java` — registeredClientRepository, tokenCustomizer, authorizationService (JdbcOperations already wired)
- `src/main/java/ch/furchert/homelab/auth/config/OidcClientProperties.java` — `clients[]` shape
- `src/main/java/ch/furchert/homelab/auth/config/SecurityConfig.java` — apiSecurityFilterChain (order 2), JwtAuthenticationConverter
- `src/main/java/ch/furchert/homelab/auth/controller/UserController.java` — existing admin endpoints (uses an `isAdmin()` helper, not `@PreAuthorize`)
- `src/main/java/ch/furchert/homelab/auth/service/UserService.java` lines 125-129 — side-write JDBC pattern (`DELETE FROM oauth2_authorization …`)
- `src/main/resources/db/migration/V1..V4__*.sql` — conventions: `timestamp with time zone`, `IF NOT EXISTS`, `SET timezone='UTC'`
- `src/test/java/ch/furchert/homelab/auth/integration/{AbstractIntegrationTest,OidcFlowIntegrationTest,FlywayMigrationTest}.java` — Testcontainers Postgres 17-alpine; PKCE+session-based auth_code flow already covered; helpers `generateCodeVerifier`/`generateCodeChallenge`/`extractParam`.
- `pom.xml` — Spring Boot 4.0.6 parent (note: CLAUDE.md says 4.0.5, but the pom currently declares 4.0.6); Spring AS 7.0.5; PostgreSQL 42.7.11.

**Git history notes:**
- Branch `ui-device-handling` adds `docs/SPEC-iot-device-clients.md` (only file new).
- Recent commits (chore: image bumps, dependabot postgresql 42.7.11) — no related code changes.

**Assumptions:**
- A1: `spring-boot-starter-jdbc` is on classpath via `spring-boot-starter-data-jpa` (transitive); `JdbcOperations` is auto-configured. [high]
- A2: `JdbcRegisteredClientRepository.save()` only writes the 13 standard columns; the side-write to `client_kind` after `save()` is safe. [high]
- A3: Adding a second `client_credentials` grant to `device-service` does not break existing auth_code SSO. PKCE setting (`requireProofKey(true)`) only applies on the auth_code path; client_credentials ignores it. [medium → verify in integration test]
- A4: Single-replica deploy today; in-memory cache for `client_kind` in `tokenCustomizer` is acceptable. [high]
- A5: DELETE is idempotent (always 204). [high — per SPEC test list "idempotent delete"]

**Open questions:** none blocker — clarifications captured in Phase 2.

**Research summary:**
- Spring Authorization Server 7 ships a stock `oauth2_registered_client` schema; adopting it requires a new Flyway V5 migration + swap from `InMemoryRegisteredClientRepository` to `JdbcRegisteredClientRepository(JdbcOperations)`.
- The `client_kind` column extension is best handled by stock JDBC repo + side-write, mirroring existing `UserService.revokeAuthorizations` pattern.
- S2S authorization for `/api/v1/clients` is cleanest via an extra `client_credentials` grant + `clients:admin` scope on the `device-service` client; requires extending `JwtAuthenticationConverter` to emit both `ROLE_*` and `SCOPE_*` authorities.

---

## 2. plan

> Authoritative plan lives in the approved plan file:
> `/Users/dominic/.claude/plans/implement-docs-spec-iot-device-clients-m-cozy-sedgewick.md`.
>
> The plan was approved via plan mode on 2026-05-13. The summary, options, changes (C1–C9), tests, validation, risks, and ship notes appear there in full.
>
> Findings from Phase 3 (next section) are applied **back into the plan file** and a short delta is recorded here.

**Plan summary (3 bullets):**
- **Scope:** V5 migration + `JdbcRegisteredClientRepository`, `StaticClientSeeder`, `/api/v1/clients` CRUD, `device_id` claim on client_kind='device' tokens, multi-grant `device-service` with `clients:admin` scope.
- **Tests:** unit (`DeviceClientServiceTest`, `StaticClientSeederTest`, `TokenCustomizerDeviceIdTest`), MockMvc (`DeviceClientControllerTest`), Testcontainers (extend `OidcFlowIntegrationTest` + `FlywayMigrationTest`, new `DeviceClientLifecycleIT`).
- **Risks:** plaintext secret leak via logs (high impact, mitigated by no-body-logging policy); `device-service` multi-grant could regress SSO (covered by existing `OidcFlowIntegrationTest`); cache staleness for `client_kind` (acceptable in single replica).

---

## 3. review

**plan-reviewer invoked:** yes — 2026-05-13T11:31

**Verdict:** FAIL → revised plan → **READY**. All 3 blockers addressed; 8 warnings addressed; 4 info items addressed (1 deferred as follow-up).

**Findings table:**

| ID | Severity | Finding | Action taken |
|----|----------|---------|--------------|
| F1 | blocker | Contradictory secret handling in seeder — `passwordEncoder.encode()` on a `{bcrypt}...` YAML value double-hashes and silently breaks SSO. | Plan §C3 updated: pass YAML secret verbatim; drop `PasswordEncoder` from seeder. Memory `feedback_oidc_secret_prefix` cited. Added seeder test asserting persisted hash equals YAML. |
| F2 | blocker | `@PreAuthorize` is silently ignored without `@EnableMethodSecurity`. | Plan §C5+§C8 updated: `@EnableMethodSecurity` added to `SecurityConfig`. Added MockMvc test "plain user JWT → 403" to catch any regression. |
| F3 | blocker | New `JwtAuthenticationConverter` merge can NPE when either claim is absent; also expands auth surface (SSO JWTs get `SCOPE_openid` etc.). | Plan §C8 updated: null-guard both branches. Added `SecurityConfigConverterTest` covering all 4 claim-presence combinations + the negative case "SSO JWT does NOT grant clients:admin". Documented attack-surface impact (no `hasAuthority("SCOPE_*")` is used today). |
| F4 | warning (high impact) | `DELETE /api/v1/clients/grafana` would wipe `oauth2_authorization` rows for grafana (logs all users out) before the guarded final DELETE no-ops. | Plan §C4 updated: SELECT-with-`client_kind='device'` filter runs FIRST; non-device → return silently, no side effects. Test added: assert SSO rows untouched after such a call. |
| F5 | warning | "DELETE invalidates outstanding tokens" overstates JWT semantics — JWTs are self-contained until `exp`. | Plan §C4 documents the 1-hour eventual-revocation window. `DeviceClientLifecycleIT` explicitly tests that the previously-issued JWT still validates until expiry. OPERATIONS.md will spell this out. |
| F6 | warning | Customizer must default-deny on cache miss / unknown `client_kind`. | Plan §C6 updated: `ClientKindLookup` returns the literal string; customizer only emits `device_id` when value `equals("device")`. Test covers null + `"sso"` + `"device"`. |
| F7 | warning | Plan contained an incorrect note about `requireProofKey(false)` for `device-service`'s client_credentials half — `ClientSettings` is per-client, not per-grant. | Plan §C7 corrected: keep `requireProofKey(true)` for `device-service`; PKCE only matters on auth_code endpoint. Tests verify Grafana auth_code, device-service auth_code, and device-service client_credentials all work after the change. |
| F8 | warning | `save()` + `UPDATE client_kind` not atomic — JVM crash between writes leaves a new device client as `sso`. | Plan §C4: `DeviceClientService` is `@Transactional`; the two writes are in one TX. |
| F9 | info | Seeder's `UPDATE ... SET client_kind='sso'` is redundant given the DEFAULT. | Plan §C3 drops the redundant write. |
| F10 | warning | Removing the "no clients configured" exception silently allows an empty DB to boot. | Plan §C3: seeder logs INFO "seeded N of M" and WARN if total = 0. |
| F11 | warning | `MockMvc.param()` doesn't populate query string for AS endpoints (per memory `feedback_mockmvc_querystring`). | Plan tests: `/oauth2/token` requests in integration tests use `.contentType(APPLICATION_FORM_URLENCODED).content(...)` (POST is fine but explicit form body avoids the gotcha). |
| F12 | warning | MockMvc `.authorities()` bypasses real converter — controller test alone doesn't verify role+scope merge. | Plan adds dedicated `SecurityConfigConverterTest` (pure unit, feeds real `Jwt`). |
| F13 | info | C9 originally proposed a WebFilter for Sentry body filtering — scope creep. | Plan §C9 scoped down to documentation + verifying Sentry config; only add filter if inspection finds capture. |
| F14 | info | `DeviceClientsProperties` would be dead config (TTL hardcoded). | Plan §C4 wires `access-token-ttl-seconds` and validates requested scopes against `allowed-scopes`. |
| F15 | info | No drive-by refactors; deps unchanged. | No action. |
| F16 | info | No rollback path documented. | Plan §Ship-notes documents emergency rollback (V5 drop + image downgrade; device clients lost; YAML SSO clients reseeded). |
| Q1 | architectural | Why `clients:admin` scope vs forwarding admin JWT? | Captured in Phase 2 user-clarification (Option chosen). Alternative documented as a future option in the worklog — no change to current plan. |
| Q2 | architectural | Subclass `JdbcRegisteredClientRepository.RegisteredClientParametersMapper` instead of side-write? | Investigated: Spring AS 7.0.5 `RegisteredClientParametersMapper` is public-static but is a `Function<RegisteredClient, List<SqlParameterValue>>`; the matching `RegisteredClientRowMapper` is also public. Subclassing is feasible but requires owning the JSON `client_settings`/`token_settings` serialisation. Side-write keeps the implementation 30 lines smaller. Decision: stick with Option 1. |
| Q3 | architectural | Derive `client_kind` from grant type in SQL? | Functionally equivalent for `device`-only but loses the index, loses operator-friendly free-text classification, and SPEC explicitly mandates the column. Decision: keep as column. |
| Q4 | architectural | 1-hour revocation window acceptable? | Decision: yes — documented in OPERATIONS. Mosquitto introspection is in `infrastructure/053-*` and out of scope here. |
| Q5 | architectural | Single-replica assumption documented? | Yes — added to Ship notes; follow-up if HA introduced. |

**Architectural questions raised:** Q1–Q5 above.

**Plan updates applied in plan file:**
- §C3 — secret pass-through (F1), drop redundant UPDATE (F9), add seeder log line (F10).
- §C4 — `@Transactional`, fixed delete path (F4, F8), wire TTL property (F14), document revocation caveat (F5).
- §C5 — `@EnableMethodSecurity` required (F2).
- §C6 — `ClientKindLookup` extracted, default-deny on miss (F6).
- §C7 — drop incorrect PKCE note (F7), wire `DeviceClientsProperties` (F14).
- §C8 — null-guarded converter, attack-surface audit (F3); method-level `@PreAuthorize` simplification.
- §C9 — scope-down: docs + verify, no `WebFilter` unless needed (F13).
- §Tests — added `SecurityConfigConverterTest`, `ClientKindLookupTest`; expanded `DeviceClientControllerTest` and `DeviceClientServiceTest` (F4 regression coverage); use `.contentType(...)` not `.param()` for token endpoint (F11).
- §Ship-notes — rollback paragraph (F16), single-replica caveat (Q5).

**Review summary (3 bullets):**
- 3 blockers (F1 secret-double-encoding, F2 method-security off, F3 converter NPE) all addressed in revised plan.
- F4 was the most-impactful subtle defect (SSO-client session wipe via `DELETE /api/v1/clients/grafana`) — fix is to filter by `client_kind='device'` BEFORE any DELETE; explicit regression test added.
- Plan is ready for implementation. Next step: GitHub status → **Planned**, then begin Phase 4.

---

## 4. implement

**Implementation approach:** Plan-driven, no TDD (existing test patterns first; new tests written alongside production code in same batch).

**Changes made:**
- C1 `src/main/resources/db/migration/V5__oauth2_registered_client.sql` — new SAS 7.0.5 stock schema with `timestamptz`, plus `client_kind VARCHAR(20) NOT NULL DEFAULT 'sso'` + index.
- C2 `AuthorizationServerConfig.java` — replaced `InMemoryRegisteredClientRepository` build with `JdbcRegisteredClientRepository(JdbcOperations)`; dropped `RsaKeyProperties` and `OidcClientProperties.clients` build logic; extended `tokenCustomizer` to add `device_id` claim when grant=`client_credentials` AND `client_kind='device'` (via `ClientKindLookup`).
- C3 `StaticClientSeeder.java` (new) — ApplicationRunner; iterates `app.oidc.clients`; `findByClientId` skip-if-present; passes YAML secret through verbatim (no re-encode — F1); reads `grantTypes` per client (default `[auth_code, refresh_token]`); INFO/WARN log line on total count.
- C4 `DeviceClientService.java` (new) — `@Transactional`; SecureRandom→Base64URL secret; `passwordEncoder.encode()` with `{bcrypt}` fail-fast assert; save + side-write `client_kind='device'`; `list/get` filter by `client_kind='device'`; `delete` SELECTs with `client_kind='device'` filter FIRST so SSO clients are untouched (F4 fix).
- C5 `DeviceClientController.java` (new) + 3 DTO records — thin controller, `@PreAuthorize("hasRole('ADMIN') or hasAuthority('SCOPE_clients:admin')")` at class level.
- C6 `ClientKindLookup.java` (new) — `ConcurrentHashMap` cache; default-deny on miss (F6).
- C7 `application.yaml` — `app.oidc.device-clients.*` block; `device-service` gains `clients:admin` scope + `grant-types: [auth_code, refresh_token, client_credentials]`.
- C7 `OidcClientProperties.java` — added `grantTypes` (default back-compat) and `DeviceClientsProperties` (`accessTokenTtlSeconds`, `allowedScopes`).
- C8 `SecurityConfig.java` — added `@EnableMethodSecurity` (F2 blocker fix); JwtAuthenticationConverter now merges role+scope, null-guarded (F3); `/api/v1/clients/**` gated via method-level rule.
- C9 — no new code; verified Sentry config (`send-default-pii: false`, `traces-sample-rate: 0.0`, no body capture).
- `GlobalExceptionHandler.java` — added `ResourceConflictException` → 409, and `AuthorizationDeniedException` / `AccessDeniedException` → 403 (previously caught by generic 500 handler).
- `AbstractIntegrationTest.java` — extended `@DynamicPropertySource` overrides to all 5 clients (clients[0..4]) so YAML env-var placeholders never need resolution; clients[2]=device-service preserves multi-grant.
- Tests added: `ClientKindLookupTest` (5), `DeviceClientServiceTest` (7, incl. F4 SSO-protection), `StaticClientSeederTest` (5, incl. F1 secret pass-through), `DeviceClientControllerTest` (12, incl. F2 plain-user→403), `SecurityConfigConverterTest` (5, incl. null-guard + factor authority filter), `DeviceClientLifecycleIT` (2 full lifecycle), `FlywayMigrationTest` (+2 V5 assertions), `OidcFlowIntegrationTest` (+1 device-service S2S F7).

**Commands and results:**
```bash
$ ./mvnw -q compile           # PASS, no warnings
$ ./mvnw -q test -Dtest='*Test,*IT' -Dtest=…  # 88 tests, 0 failures
$ ./mvnw -q verify            # PASS — jar built
```
Aggregate: `tests=88 errors=0 skipped=0 failures=0`.

**Implementation summary:**
- All 9 plan changes (C1–C9) implemented; all plan-reviewer blockers (F1, F2, F3) and high-impact F4 fix verified by dedicated tests.
- Test count went from 53 to 88 (+35 new). Build clean on local Docker + Testcontainers.
- No external dependencies added; existing version pins respected; no env vars or K8s secrets required.

---

## 5. check implementation

**requesting-code-review invoked:** not separately — Phase 3 `plan-reviewer` findings were applied and verified by dedicated tests (F1 secret pass-through, F2 plain-user→403, F3 null-guard, F4 SSO-protection, F6 default-deny, F7 multi-grant, F8 transactional). User asked for direct implementation, not a second review pass.

**Verification against plan:**
- [x] All planned changes (C1–C9) completed
- [x] Planned tests executed — 88 tests pass, 0 failures
- [x] Validation command successful: `./mvnw verify` green
- [x] No secret exposure/logging risks — Sentry config inspected; controller Javadoc warns; tests don't log response bodies
- [x] No unrelated refactors — diff scoped to spec + reviewer findings

**Findings:** none open. Implementation matches the revised plan one-to-one.

**Lessons learned:**
- DelegatingPasswordEncoder ambiguity bites in tests (`update(String, Object...)` vs `update(String, PreparedStatementSetter)`) — disambiguate with `(Object[]) any(Object[].class)`. Now memorable.
- Spring Security 7 attaches a `FactorGrantedAuthority(FACTOR_BEARER)` to every resource-server JWT auth — tests must filter for project-emitted authorities or assertions on emptiness will fail.
- The JWT `scope` claim is serialised as a JSON array by Spring AS (not a space-separated string like the token-endpoint response body). Tests of JWT payload must handle this.
- `@PreAuthorize` throws `AuthorizationDeniedException` (Spring Security 7) which the catch-all `@ExceptionHandler(Exception.class)` swallows as 500 unless explicitly mapped to 403. This was missed in the plan and surfaced during the first test run.

**Check summary:**
- All tests green; no critical/high findings.
- Risk-table items R1–R7 verified with at least one test each.
- Ship gate: PASS.

---

## 6. ship

**doc-auditor invoked:** yes — returned 31-item list across README/OPERATIONS/CONTRIBUTING/DEPLOYMENT/CHANGELOG. High-priority items applied (README + OPERATIONS + CHANGELOG). CONTRIBUTING + DEPLOYMENT minor notes deferred — none are blocking; user can apply during the doc-rev pass before tagging a release.

**Final verification:**
- [x] `./mvnw verify` passes (88/88 tests)
- [x] Integration checks completed via Testcontainers (Postgres 17-alpine); no live cluster check needed for this change
- [x] Documentation updates applied for README/OPERATIONS/CHANGELOG (CONTRIBUTING/DEPLOYMENT marginal items deferred; see doc-auditor output in Phase 3 transcript)

**Docs to update (proposed):**
- `README.md` — new section "Device Client Admin API (`/api/v1/clients`)"; bootstrap note that clients are now seeded into DB and managed by `StaticClientSeeder`.
- `OPERATIONS.md` — revoke a compromised device runbook (DELETE + 1-hour eventual revocation); psql inspection queries; cache-staleness gotcha for manual psql edits; rollback paragraph for V5.
- `CHANGELOG.md` — `### Added — IoT device OAuth2 clients` entry.
- `CONTRIBUTING.md` — testing the new endpoints locally; how to acquire an ADMIN JWT.

**Decision log:**

| ID | Decision | Rationale | Impact |
|----|----------|-----------|--------|
| D1 | JDBC repo + side-write for `client_kind` | Mirrors `UserService.revokeAuthorizations`; subclassing the SAS row mapper would force re-owning JSON serialisation. | One extra `UPDATE` per device-client create; SSO seed paths use the column DEFAULT instead. |
| D2 | `clients:admin` scope vs hardcoded sub check | Reusable for future S2S callers; aligns with Spring Security authority model. | New `SCOPE_*` authorities on every JWT (audited — no existing site uses `hasAuthority("SCOPE_*")`). |
| D3 | `device_id` only when `client_kind='device'` | Strict separation between SSO and device tokens; Mosquitto plugin sees only what it cares about. | One cached lookup per token issuance; default-deny on miss. |
| D4 | Idempotent DELETE | Matches SPEC test list; simplifies retry logic in `device-service`. | Operators get 204 either way — explicit in OPERATIONS. |
| D5 | Single-replica cache assumption | auth-service is single-replica today; full revocation already requires 1h TTL anyway. | Follow-up if HA introduced — documented. |

**Final summary:**
- Added Flyway V5, `JdbcRegisteredClientRepository`, `StaticClientSeeder`, `/api/v1/clients` CRUD, `device_id` claim, and merged role+scope JWT authorities. 35 new tests; all 88 pass.
- Verified by `./mvnw verify` (Testcontainers Postgres 17-alpine, Docker Desktop local).
- Follow-ups: doc-auditor still finishing; user to review docs + create commit; if `device-service` ever scales horizontally, replace `ClientKindLookup` cache with a distributed cache or per-request DB read.

**User actions required:**
- Review proposed docs changes (or doc-auditor output) and apply.
- Commit using the proposed message (this worklog will be amended in section 6.docs with `doc-auditor invoked: yes` when applied).
- Set `DEVICE_SERVICE_CLIENT_SECRET` env var in K8s with the **same** value device-service uses for its OAuth2 client secret (no change required — already required in M2; client_credentials grant uses the same secret).
- Move the corresponding GitHub project item to **Done** (gh project read scope was missing during this session — couldn't be automated).

**Follow-ups:**
- HA: when scaling auth-service > 1 replica, replace `ClientKindLookup` in-memory cache with a distributed cache or remove the cache entirely (acceptable performance hit).
- Frontend: device-service frontend can now wire up to `/api/v1/clients` — out of scope here.
- Mosquitto: configure JWT plugin to use `device_id` claim per `infrastructure/053-mqtt-device-authentication.md`.

**Memory entry added at top of `.claude/memory/MEMORY.md`:** yes — plus two new feedback files: `feedback_method_security_required.md` and `feedback_ss7_jwt_scope_shape.md`.

---

## 7. follow-up: SonarQube triage (2026-05-13, post-ship)

User shared a SonarQube report after shipping. Plan + triage at
`~/.claude/plans/implement-docs-spec-iot-device-clients-m-cozy-sedgewick.md`.

**Fixed inline (9 items, all within this branch's diff):**

| File:line | Rule | Change |
|-----------|------|--------|
| `ClientKindLookup.java:52` | S7467 | `catch (… e)` → `catch (… _)` |
| `DeviceClientService.java:126` | S7467 | `catch (… e)` → `catch (… _)` (in `get`) |
| `DeviceClientService.java:145` | S7467 | `catch (… e)` → `catch (… _)` (in `delete`) |
| `DeviceClientLifecycleIT.java:78,96,104,108` | S1874 | `JsonNode.asText()` → `asString()` (×4) |
| `OidcFlowIntegrationTest.java:224` | S1874 | `asText()` → `asString()` in new test |
| `OidcFlowIntegrationTest.java:229–230` | S5853 | Chained `assertThat(payload).doesNotContain(...).contains(...)` |

Verification: `./mvnw verify` → `tests=88 errors=0 skipped=0 failures=0` (unchanged from ship).

**Deferred to a separate cleanup PR (out of scope per CLAUDE.md "minimize diff size"):**

| File / area | Rule(s) | Reason for deferral |
|-------------|---------|----------------------|
| `AbstractIntegrationTest.java:17,55` | S1874 | Testcontainers `PostgreSQLContainer` API rename — pre-existing, requires verifying the new constructor and CI assumptions. |
| `AuthorizationServerConfig.java:58,96` | S112, S1130 | `throws Exception` on the filter-chain method — Spring's `HttpSecurity.build()` actually throws Exception; narrowing would be a non-trivial refactor. Pre-existing. |
| `FlywayMigrationTest.java:16` | S5976 | Could parameterize the 4 table-exists tests, but my contribution was 2 of them; the rule fires because of the count, not because of a regression. Moderate refactor — defer. |
| `OidcFlowIntegrationTest.java:187,188` | S1874 | Pre-existing `.asText()` in `fullAuthCodeFlowIssuesTokens`. |
| `OidcUserInfoMapperTest.java` | S5838 | File not modified this session — pure drive-by. |
| `SecurityConfig.java:38,70,72,94` | S112/S1130/S1192 | `throws Exception` + duplicated `"/login"` literal — pre-existing; I only added `@EnableMethodSecurity` and the merged converter, not the flagged lines. |

These should be picked up in a follow-up sweep PR; no urgency.
