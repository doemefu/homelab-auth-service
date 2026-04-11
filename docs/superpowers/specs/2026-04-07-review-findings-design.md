# Design: Address Code Review Findings

**Date:** 2026-04-07
**Scope:** 13 targeted fixes across security, correctness, deployment, and testing

## Context

Full repository review identified 15 findings. After discussion, 2 were dropped (Java 25 kept as-is, Swagger intentionally behind auth). The remaining 13 are addressed here.

## Security Fixes

### S1: Password max-length validation (BCrypt truncation)

Add `@Size(max = 72)` to password fields in `CreateUserRequest`, `ResetPasswordRequest`, and `LoginRequest`. BCrypt silently truncates at 72 bytes — validation prevents user confusion. Adding it to `LoginRequest` ensures consistency: a user cannot accidentally log in with a truncated prefix of their password.

**Files:** `dto/CreateUserRequest.java`, `dto/ResetPasswordRequest.java`, `dto/LoginRequest.java`

### S2: Rate limiting on auth endpoints

Add Bucket4j-based rate limiting filter on `/api/v1/auth/login` and `/api/v1/auth/refresh`.

- **New dependency:** `com.bucket4j:bucket4j-core` (pinned version)
- **Implementation:** Servlet filter registered in `SecurityConfig`, IP-based tracking via Caffeine cache (already a transitive Spring Boot dependency — no new dep needed for the cache)
- **Eviction:** Caffeine cache with `expireAfterAccess(5, MINUTES)` and `maximumSize(10_000)` — prevents unbounded memory growth from unique IPs
- **Limits:** 10 requests per minute per IP on login, 20 per minute on refresh
- **Response:** HTTP 429 with JSON error body matching existing error format

**Files:** new `security/RateLimitingFilter.java`, `pom.xml`, `config/SecurityConfig.java`

### S3: Pessimistic lock on refresh token lookup

Add `@Lock(LockModeType.PESSIMISTIC_WRITE)` to `RefreshTokenRepository.findByToken()`. Prevents race condition where two concurrent refresh requests with the same token both succeed.

**Note:** Pessimistic locks require an active transaction. `AuthService.refresh()` is already `@Transactional`, so this works. A code comment on the repository method will document this dependency.

**Files:** `repository/RefreshTokenRepository.java`

### S4: Commit test RSA keys

Generate a 2048-bit RSA key pair and commit to `src/test/resources/keys/`. These are test-only keys, not secrets.

**Files:** new `src/test/resources/keys/private.pem`, `src/test/resources/keys/public.pem`

## Correctness Fixes

### C1: Convert role to enum

Create `Role` enum (`USER`, `ADMIN`) with `@Enumerated(EnumType.STRING)` on the entity. No Flyway migration needed — the existing `VARCHAR(10)` column already stores `"USER"` and `"ADMIN"` strings.

**Changes:**
- New `entity/Role.java` enum with values `USER`, `ADMIN`
- `User.role` field: `String` -> `Role` with `@Enumerated(EnumType.STRING)`
- `CreateUserRequest.role`: replace `@Pattern(regexp = "USER|ADMIN") String` with `Role` enum (Jackson deserializes enum names from JSON strings natively)
- `UpdateUserRequest.role`: same — `@Pattern` String -> `Role` enum
- `UserResponse.role`: keep as `String` in the API response for backward compatibility, use `user.getRole().name()` in the factory method
- `UserService`: remove `VALID_ROLES` set for role (keep `VALID_STATUSES` and status as String for now), use enum directly. Invalid enum values in the request body produce a Jackson `HttpMessageNotReadableException`
- `GlobalExceptionHandler`: add `@ExceptionHandler(HttpMessageNotReadableException.class)` returning 400 with "Invalid request body" message. Without this, invalid enum values would fall through to the catch-all 500 handler
- `JwtService.generateAccessToken`: change parameter from `String role` to `Role role`, call `role.name()` for the JWT claim
- `AuthService.login`: pass `user.getRole()` (now a `Role` enum) to `jwtService.generateAccessToken`
- `JwtAuthenticationFilter`: `claims.get("role", String.class)` stays as String — JWT claims are strings, prefix with `ROLE_` as before
- `CustomUserDetailsService`: use `user.getRole().name()` for authority string
- All test files updated to use `Role.USER` / `Role.ADMIN` instead of string literals
- `UserServiceTest`: invalid-role tests (`createUser_withInvalidRole`, `updateUser_withInvalidRole`) are removed — invalid enum values are now rejected at the Jackson deserialization layer (controller level) before reaching the service. Equivalent coverage is added to `UserControllerTest` or `AuthControllerTest` as a controller-level test sending an invalid role string in JSON

### C2: Remove AccessDeniedException handler from GlobalExceptionHandler

Remove `handleAccessDenied()` method. Spring Security's `ExceptionTranslationFilter` will handle all `AccessDeniedException` uniformly via the `accessDeniedHandler` configured in `SecurityConfig`.

**Files:** `exception/GlobalExceptionHandler.java`

### C3: Add logging to catch-all exception handler

Add `private static final Logger log = LoggerFactory.getLogger(...)` and `log.error("Unhandled exception", ex)` in `handleGeneric()`. Does not leak details to the client — only logs server-side.

**Files:** `exception/GlobalExceptionHandler.java`

## Deployment Fixes

### D1: Add database URL to K8s deployment

Add `SPRING_DATASOURCE_URL` environment variable. Use a placeholder value (`jdbc:postgresql://postgres-service:5432/homelabdb`) with a comment indicating it should be adjusted to the actual in-cluster PostgreSQL service name.

**Files:** `k8s/deployment.yaml`

### D2: Add startup probe

Add `startupProbe` with higher `failureThreshold` (30) and `periodSeconds` (2) to allow up to 60s for JVM + Spring Boot startup without liveness probe killing the pod.

**Files:** `k8s/deployment.yaml`

## Testing Fixes

### T1: Fix UserControllerTest principal type

`getUser_whenNotFound_returns404` uses `.with(user("admin").roles("ADMIN"))` which sets a `UserDetails` principal. Change to use `UsernamePasswordAuthenticationToken` with a String principal, matching the runtime behavior of `JwtAuthenticationFilter`.

**Files:** `controller/UserControllerTest.java`

### T2: Set timestamps on test User entities

Set `createdAt` and `updatedAt` on manually constructed `User` objects in `UserServiceTest` to prevent null values propagating through `UserResponse.from()`.

**Files:** `service/UserServiceTest.java`

## Documentation

### Doc1: Swagger intentionally behind auth

Add a comment in `SecurityConfig` near the permit list explaining Swagger is intentionally not permitted without auth.

### Doc2: K8s image tag placeholder

Add a comment in `k8s/deployment.yaml` explaining the `<SHA>` placeholder is substituted by CI/CD.

## Out of Scope

- Java 25: kept as-is (user decision)
- Swagger permit list: intentionally behind auth (user decision)

## New Dependencies

| Dependency | Version | Scope |
|------------|---------|-------|
| `com.bucket4j:bucket4j_jdk17-core` | 8.17.0 | compile |

## Flyway Migrations

None required. Role enum maps to existing VARCHAR column with identical string values.
