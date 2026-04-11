# Review Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address 13 code review findings across security, correctness, deployment, and testing.

**Architecture:** Targeted fixes only — no architectural changes. Each task is self-contained. Tasks are ordered to minimize merge conflicts: infrastructure first (keys, deps), then model layer (enum), then security, then tests, then deployment.

**Tech Stack:** Java 25, Spring Boot 4.0.5, Spring Security 7.0, jjwt 0.12.6, Bucket4j 8.17.0, PostgreSQL, Flyway, Testcontainers

**Spec:** `docs/superpowers/specs/2026-04-07-review-findings-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/test/resources/keys/private.pem` | Test-only RSA private key |
| Create | `src/test/resources/keys/public.pem` | Test-only RSA public key |
| Create | `src/main/java/ch/furchert/homelab/auth/entity/Role.java` | Role enum |
| Create | `src/main/java/ch/furchert/homelab/auth/security/RateLimitingFilter.java` | Bucket4j rate limiting filter |
| Modify | `pom.xml` | Add Bucket4j dependency |
| Modify | `src/main/java/ch/furchert/homelab/auth/entity/User.java` | Role field String -> enum |
| Modify | `src/main/java/ch/furchert/homelab/auth/dto/CreateUserRequest.java` | Role type + password max length |
| Modify | `src/main/java/ch/furchert/homelab/auth/dto/UpdateUserRequest.java` | Role type |
| Modify | `src/main/java/ch/furchert/homelab/auth/dto/LoginRequest.java` | Password max length |
| Modify | `src/main/java/ch/furchert/homelab/auth/dto/ResetPasswordRequest.java` | Password max length |
| Modify | `src/main/java/ch/furchert/homelab/auth/dto/UserResponse.java` | role getter uses .name() |
| Modify | `src/main/java/ch/furchert/homelab/auth/service/UserService.java` | Remove VALID_ROLES, use enum |
| Modify | `src/main/java/ch/furchert/homelab/auth/service/AuthService.java` | Pass Role enum to JwtService |
| Modify | `src/main/java/ch/furchert/homelab/auth/security/JwtService.java` | Accept Role enum |
| Modify | `src/main/java/ch/furchert/homelab/auth/security/CustomUserDetailsService.java` | Use .name() on Role enum |
| Modify | `src/main/java/ch/furchert/homelab/auth/repository/RefreshTokenRepository.java` | Add pessimistic lock |
| Modify | `src/main/java/ch/furchert/homelab/auth/exception/GlobalExceptionHandler.java` | Remove AccessDenied handler, add logging, add HttpMessageNotReadable handler |
| Modify | `src/main/java/ch/furchert/homelab/auth/config/SecurityConfig.java` | Register rate limiter, add Swagger comment |
| Modify | `src/test/java/ch/furchert/homelab/auth/service/UserServiceTest.java` | Fix timestamps, update role refs, move invalid-role tests |
| Modify | `src/test/java/ch/furchert/homelab/auth/service/AuthServiceTest.java` | Update role refs |
| Modify | `src/test/java/ch/furchert/homelab/auth/controller/UserControllerTest.java` | Fix principal type, add invalid-role test |
| Modify | `src/test/java/ch/furchert/homelab/auth/controller/AuthControllerTest.java` | Update if needed for role |
| Modify | `src/test/java/ch/furchert/homelab/auth/integration/AuthIntegrationTest.java` | Update role refs |
| Modify | `src/test/java/ch/furchert/homelab/auth/integration/SecurityConfigTest.java` | Update role refs |
| Modify | `k8s/deployment.yaml` | Add DB URL, startup probe, image tag comment |

---

### Task 1: Generate and commit test RSA keys

**Files:**
- Create: `src/test/resources/keys/private.pem`
- Create: `src/test/resources/keys/public.pem`

- [ ] **Step 1: Create the keys directory and generate a 2048-bit RSA key pair**

Run:
```bash
mkdir -p src/test/resources/keys
openssl genrsa -out src/test/resources/keys/private.pem 2048
openssl rsa -in src/test/resources/keys/private.pem -pubout -out src/test/resources/keys/public.pem
```
Expected: Two PEM files created in `src/test/resources/keys/`.

- [ ] **Step 2: Convert the private key to PKCS#8 format (required by Java)**

The `RsaKeyProvider` uses `PKCS8EncodedKeySpec`, so the private key must be PKCS#8:
```bash
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in src/test/resources/keys/private.pem -out src/test/resources/keys/private_pkcs8.pem
mv src/test/resources/keys/private_pkcs8.pem src/test/resources/keys/private.pem
```
Expected: `private.pem` is now in PKCS#8 format (header says `BEGIN PRIVATE KEY`, not `BEGIN RSA PRIVATE KEY`).

- [ ] **Step 3: Verify keys are loadable**

Run:
```bash
openssl rsa -in src/test/resources/keys/private.pem -check -noout
openssl rsa -pubin -in src/test/resources/keys/public.pem -noout
```
Expected: Both commands succeed with no errors.

- [ ] **Step 4: Commit**

```
feat: add test RSA keys for integration tests
```

---

### Task 2: Add Role enum and update entity

**Files:**
- Create: `src/main/java/ch/furchert/homelab/auth/entity/Role.java`
- Modify: `src/main/java/ch/furchert/homelab/auth/entity/User.java:30-31`

- [ ] **Step 1: Create the Role enum**

Create `src/main/java/ch/furchert/homelab/auth/entity/Role.java`:
```java
package ch.furchert.homelab.auth.entity;

public enum Role {
    USER,
    ADMIN
}
```

- [ ] **Step 2: Update User entity to use Role enum**

In `src/main/java/ch/furchert/homelab/auth/entity/User.java`, change lines 30-31 from:
```java
    @Column(nullable = false, length = 10)
    private String role = "USER";
```
to:
```java
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Role role = Role.USER;
```

Add import at top:
```java
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
```

- [ ] **Step 3: Compile to verify**

Run:
```bash
./mvnw compile -q 2>&1 | head -30
```
Expected: Compilation errors in files that still use `String` for role — this is expected, we fix them in subsequent tasks.

- [ ] **Step 4: Commit**

```
refactor: introduce Role enum for type-safe role handling
```

---

### Task 3: Update DTOs for Role enum and password max-length

**Files:**
- Modify: `src/main/java/ch/furchert/homelab/auth/dto/CreateUserRequest.java:12`
- Modify: `src/main/java/ch/furchert/homelab/auth/dto/UpdateUserRequest.java:10`
- Modify: `src/main/java/ch/furchert/homelab/auth/dto/LoginRequest.java:7`
- Modify: `src/main/java/ch/furchert/homelab/auth/dto/ResetPasswordRequest.java:8`
- Modify: `src/main/java/ch/furchert/homelab/auth/dto/UserResponse.java:16-25`

- [ ] **Step 1: Update CreateUserRequest — Role enum + password max length**

Replace entire file `src/main/java/ch/furchert/homelab/auth/dto/CreateUserRequest.java`:
```java
package ch.furchert.homelab.auth.dto;

import ch.furchert.homelab.auth.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
        @NotBlank @Size(min = 3, max = 50) String username,
        @NotBlank @Email @Size(max = 100) String email,
        @NotBlank @Size(min = 8, max = 72) String password,
        Role role
) {}
```

- [ ] **Step 2: Update UpdateUserRequest — Role enum**

Replace entire file `src/main/java/ch/furchert/homelab/auth/dto/UpdateUserRequest.java`:
```java
package ch.furchert.homelab.auth.dto;

import ch.furchert.homelab.auth.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @Size(min = 3, max = 50) String username,
        @Email @Size(max = 100) String email,
        Role role,
        @Pattern(regexp = "ACTIVE|INACTIVE") String status
) {}
```

- [ ] **Step 3: Update LoginRequest — password max length**

Replace entire file `src/main/java/ch/furchert/homelab/auth/dto/LoginRequest.java`:
```java
package ch.furchert.homelab.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank String username,
        @NotBlank @Size(max = 72) String password
) {}
```

- [ ] **Step 4: Update ResetPasswordRequest — password max length**

Replace entire file `src/main/java/ch/furchert/homelab/auth/dto/ResetPasswordRequest.java`:
```java
package ch.furchert.homelab.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        String currentPassword,
        @NotBlank @Size(min = 8, max = 72) String newPassword
) {}
```

- [ ] **Step 5: Update UserResponse — use role.name()**

In `src/main/java/ch/furchert/homelab/auth/dto/UserResponse.java`, change the `from` method body (lines 17-25) from:
```java
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole(),
                user.getStatus(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
```
to:
```java
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                user.getStatus(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
```

- [ ] **Step 6: Commit**

```
refactor: update DTOs for Role enum and add password max-length validation
```

---

### Task 4: Update service and security layers for Role enum

**Files:**
- Modify: `src/main/java/ch/furchert/homelab/auth/service/UserService.java:21,37-46,77-81`
- Modify: `src/main/java/ch/furchert/homelab/auth/service/AuthService.java:50,78`
- Modify: `src/main/java/ch/furchert/homelab/auth/security/JwtService.java:23`
- Modify: `src/main/java/ch/furchert/homelab/auth/security/CustomUserDetailsService.java:33`

- [ ] **Step 1: Update UserService — remove VALID_ROLES, use Role enum**

In `src/main/java/ch/furchert/homelab/auth/service/UserService.java`:

Remove line 21:
```java
    private static final java.util.Set<String> VALID_ROLES = java.util.Set.of("USER", "ADMIN");
```

Replace the role handling in `createUser` (lines 37-46) — change:
```java
        String role = request.role() != null ? request.role() : "USER";
        if (!VALID_ROLES.contains(role)) {
            throw new IllegalArgumentException("Invalid role: " + role);
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(role);
```
to:
```java
        Role role = request.role() != null ? request.role() : Role.USER;

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(role);
```

Add import:
```java
import ch.furchert.homelab.auth.entity.Role;
```

Replace the role handling in `updateUser` (lines 77-81) — change:
```java
        if (request.role() != null) {
            if (!VALID_ROLES.contains(request.role())) {
                throw new IllegalArgumentException("Invalid role: " + request.role());
            }
            user.setRole(request.role());
        }
```
to:
```java
        if (request.role() != null) {
            user.setRole(request.role());
        }
```

- [ ] **Step 2: Update JwtService — accept Role enum**

In `src/main/java/ch/furchert/homelab/auth/security/JwtService.java`, change line 23 from:
```java
    public String generateAccessToken(String username, String role) {
```
to:
```java
    public String generateAccessToken(String username, Role role) {
```

Change line 29 from:
```java
                .claim(CLAIM_ROLE, role)
```
to:
```java
                .claim(CLAIM_ROLE, role.name())
```

Add import:
```java
import ch.furchert.homelab.auth.entity.Role;
```

- [ ] **Step 3: Update CustomUserDetailsService — use .name()**

In `src/main/java/ch/furchert/homelab/auth/security/CustomUserDetailsService.java`, change line 33 from:
```java
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
```
to:
```java
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
```

- [ ] **Step 4: Compile to verify all role references are consistent**

Run:
```bash
./mvnw compile -q 2>&1 | head -30
```
Expected: Main sources compile successfully. Test compilation may still fail (fixed in Task 7).

- [ ] **Step 5: Commit**

```
refactor: update service and security layers for Role enum
```

---

### Task 5: Fix GlobalExceptionHandler — remove AccessDenied handler, add logging, add HttpMessageNotReadable handler

**Files:**
- Modify: `src/main/java/ch/furchert/homelab/auth/exception/GlobalExceptionHandler.java`

- [ ] **Step 1: Replace the entire GlobalExceptionHandler**

Replace `src/main/java/ch/furchert/homelab/auth/exception/GlobalExceptionHandler.java` with:
```java
package ch.furchert.homelab.auth.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage,
                        (a, b) -> a));
        return ResponseEntity.badRequest().body(errorBody(HttpStatus.BAD_REQUEST, "Validation failed", fieldErrors));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleMessageNotReadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest()
                .body(errorBody(HttpStatus.BAD_REQUEST, "Invalid request body", null));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(errorBody(HttpStatus.UNAUTHORIZED, "Unauthorized", null));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(errorBody(HttpStatus.BAD_REQUEST, ex.getMessage(), null));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(errorBody(HttpStatus.NOT_FOUND, ex.getMessage(), null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorBody(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", null));
    }

    private Map<String, Object> errorBody(HttpStatus status, String message, Object details) {
        return details != null
                ? Map.of("status", status.value(), "error", message, "timestamp", Instant.now().toString(), "details", details)
                : Map.of("status", status.value(), "error", message, "timestamp", Instant.now().toString());
    }
}
```

Changes from original:
- Removed `AccessDeniedException` import and handler (Spring Security handles it via `SecurityConfig.accessDeniedHandler`)
- Added `HttpMessageNotReadableException` handler returning 400 (catches invalid enum values in request bodies)
- Added `Logger` field and `log.error("Unhandled exception", ex)` in catch-all handler

- [ ] **Step 2: Compile to verify**

Run:
```bash
./mvnw compile -q 2>&1 | head -30
```
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```
fix: improve GlobalExceptionHandler — remove redundant AccessDenied handler, add logging, handle malformed request bodies
```

---

### Task 6: Add pessimistic lock on refresh token lookup

**Files:**
- Modify: `src/main/java/ch/furchert/homelab/auth/repository/RefreshTokenRepository.java:15`

- [ ] **Step 1: Add @Lock annotation to findByToken**

In `src/main/java/ch/furchert/homelab/auth/repository/RefreshTokenRepository.java`, change line 15 from:
```java
    Optional<RefreshToken> findByToken(String token);
```
to:
```java
    // Pessimistic lock prevents race conditions during refresh token rotation.
    // Callers must be @Transactional (AuthService.refresh() is).
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<RefreshToken> findByToken(String token);
```

Add imports:
```java
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
```

- [ ] **Step 2: Commit**

```
fix: add pessimistic lock on refresh token lookup to prevent race condition
```

---

### Task 7: Add Bucket4j rate limiting filter

**Files:**
- Modify: `pom.xml`
- Create: `src/main/java/ch/furchert/homelab/auth/security/RateLimitingFilter.java`
- Modify: `src/main/java/ch/furchert/homelab/auth/config/SecurityConfig.java`

- [ ] **Step 1: Add Bucket4j dependency to pom.xml**

In `pom.xml`, after the springdoc dependency block (after line 93), add:
```xml
		<!-- Rate limiting -->
		<dependency>
			<groupId>com.bucket4j</groupId>
			<artifactId>bucket4j_jdk17-core</artifactId>
			<version>8.17.0</version>
		</dependency>
```

- [ ] **Step 2: Create RateLimitingFilter**

Create `src/main/java/ch/furchert/homelab/auth/security/RateLimitingFilter.java`:
```java
package ch.furchert.homelab.auth.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Set<String> RATE_LIMITED_PATHS = Set.of(
            "/api/v1/auth/login",
            "/api/v1/auth/refresh"
    );

    private static final int LOGIN_REQUESTS_PER_MINUTE = 10;
    private static final int REFRESH_REQUESTS_PER_MINUTE = 20;

    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterAccess(Duration.ofMinutes(5))
            .build();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (!RATE_LIMITED_PATHS.contains(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String ip = request.getRemoteAddr();
        String key = ip + ":" + path;
        int limit = path.endsWith("/login") ? LOGIN_REQUESTS_PER_MINUTE : REFRESH_REQUESTS_PER_MINUTE;

        Bucket bucket = buckets.get(key, k -> createBucket(limit));

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
            response.getWriter().write("{\"status\":429,\"error\":\"Too many requests\",\"timestamp\":\""
                    + java.time.Instant.now() + "\"}");
        }
    }

    private Bucket createBucket(int capacityPerMinute) {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(capacityPerMinute)
                        .refillGreedy(capacityPerMinute, Duration.ofMinutes(1))
                        .build())
                .build();
    }
}
```

- [ ] **Step 3: Register the filter in SecurityConfig**

In `src/main/java/ch/furchert/homelab/auth/config/SecurityConfig.java`, add the filter field and registration.

Add field:
```java
    private final RateLimitingFilter rateLimitingFilter;
```

The existing `@RequiredArgsConstructor` will inject both filters. In the `filterChain` method, add the rate limiter before the JWT filter. After line 57:
```java
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
```
add before it:
```java
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
```

Also add the import:
```java
import ch.furchert.homelab.auth.security.RateLimitingFilter;
```

- [ ] **Step 4: Add Swagger-behind-auth comment in SecurityConfig**

In `SecurityConfig.java`, add a comment above the permit list (before line 33):
```java
                // Note: Swagger UI (/swagger-ui/**, /api-docs/**) is intentionally NOT permitted
                // without authentication. Access requires a valid JWT.
```

- [ ] **Step 5: Compile to verify**

Run:
```bash
./mvnw compile -q 2>&1 | head -30
```
Expected: Compiles successfully.

- [ ] **Step 6: Commit**

```
feat: add Bucket4j rate limiting on login and refresh endpoints
```

---

### Task 8: Update unit tests for Role enum and fix test issues

**Files:**
- Modify: `src/test/java/ch/furchert/homelab/auth/service/UserServiceTest.java`
- Modify: `src/test/java/ch/furchert/homelab/auth/service/AuthServiceTest.java`
- Modify: `src/test/java/ch/furchert/homelab/auth/controller/UserControllerTest.java`
- Modify: `src/test/java/ch/furchert/homelab/auth/controller/AuthControllerTest.java`

- [ ] **Step 1: Update UserServiceTest — fix timestamps, update role refs, remove invalid-role tests**

In `src/test/java/ch/furchert/homelab/auth/service/UserServiceTest.java`:

Add imports:
```java
import ch.furchert.homelab.auth.entity.Role;
import java.time.Instant;
```

In `setUp()` (around line 44), after `existingUser.setStatus("ACTIVE");` add:
```java
        existingUser.setCreatedAt(Instant.now());
        existingUser.setUpdatedAt(Instant.now());
```

Update `createUser_withValidRequest_returnsUserResponse` — change:
```java
        CreateUserRequest request = new CreateUserRequest("newuser", "new@example.com", "password123", null);
```
stays the same (null role is fine — UserService defaults to `Role.USER`).

Update assertion:
```java
        assertThat(response.role()).isEqualTo("USER");
```
stays the same (UserResponse.role is still a String).

Update `createUser_withInvalidRole_throwsIllegalArgument` (lines 230-238) — **delete this entire test method**. Invalid roles are now caught by Jackson deserialization at the controller layer.

Update `updateUser_withInvalidRole_throwsIllegalArgument` (lines 240-248) — **delete this entire test method**. Same reason.

- [ ] **Step 2: Update AuthServiceTest — update role refs**

In `src/test/java/ch/furchert/homelab/auth/service/AuthServiceTest.java`:

Add import:
```java
import ch.furchert.homelab.auth.entity.Role;
```

In `setUp()`, change line 53:
```java
        user.setRole("USER");
```
to:
```java
        user.setRole(Role.USER);
```

In `login_withValidCredentials_returnsTokens`, change:
```java
        when(jwtService.generateAccessToken("testuser", "USER")).thenReturn("access-token");
```
to:
```java
        when(jwtService.generateAccessToken("testuser", Role.USER)).thenReturn("access-token");
```

In `refresh_withValidToken_rotatesAndReturnsNewTokens`, change:
```java
        when(jwtService.generateAccessToken("testuser", "USER")).thenReturn("new-access-token");
```
to:
```java
        when(jwtService.generateAccessToken("testuser", Role.USER)).thenReturn("new-access-token");
```

- [ ] **Step 3: Update UserControllerTest — fix principal type, add invalid-role test**

In `src/test/java/ch/furchert/homelab/auth/controller/UserControllerTest.java`:

Add import:
```java
import ch.furchert.homelab.auth.entity.Role;
```

Fix `getUser_whenNotFound_returns404` (lines 111-118) — change:
```java
    @Test
    void getUser_whenNotFound_returns404() throws Exception {
        when(userService.getUser(eq(99L), any(), eq(true)))
                .thenThrow(new ResourceNotFoundException("User not found: 99"));

        mockMvc.perform(get("/api/v1/users/99")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isNotFound());
    }
```
to:
```java
    @Test
    void getUser_whenNotFound_returns404() throws Exception {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        when(userService.getUser(eq(99L), eq("admin"), eq(true)))
                .thenThrow(new ResourceNotFoundException("User not found: 99"));

        mockMvc.perform(get("/api/v1/users/99")
                        .with(authentication(auth)))
                .andExpect(status().isNotFound());
    }
```

Add a new test for invalid role in request body (at the end of the class):
```java
    @Test
    void createUser_withInvalidRole_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .with(user("admin").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"testuser\",\"email\":\"test@example.com\",\"password\":\"password123\",\"role\":\"SUPERADMIN\"}")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }
```

- [ ] **Step 4: Update AuthControllerTest if needed**

Check `src/test/java/ch/furchert/homelab/auth/controller/AuthControllerTest.java` — this test mocks `AuthService` and doesn't reference `Role` directly. The `LoginRequest` and `LoginResponse` haven't changed their type signatures for existing fields. No changes needed.

- [ ] **Step 5: Run all unit tests**

Run:
```bash
./mvnw test -pl . -Dtest="*ServiceTest,*ControllerTest" -q 2>&1 | tail -20
```
Expected: All unit tests pass.

- [ ] **Step 6: Commit**

```
test: update unit tests for Role enum, fix principal type, add invalid-role controller test
```

---

### Task 9: Update integration tests

**Files:**
- Modify: `src/test/java/ch/furchert/homelab/auth/integration/AuthIntegrationTest.java`
- Modify: `src/test/java/ch/furchert/homelab/auth/integration/SecurityConfigTest.java`

- [ ] **Step 1: Check integration tests for role string references**

In `AuthIntegrationTest.java`, the `CreateUserRequest` calls use string `"USER"`:
```java
userService.createUser(new CreateUserRequest("authuser", "auth@example.com", "password123", "USER"));
```

Since `CreateUserRequest.role` is now `Role` enum, change all occurrences. In `AuthIntegrationTest.java`:

Add import:
```java
import ch.furchert.homelab.auth.entity.Role;
```

Change all `CreateUserRequest` calls — replace `"USER"` with `Role.USER` and `"ADMIN"` with `Role.ADMIN` in the role parameter position.

Lines to update:
- Line 48: `new CreateUserRequest("authuser", "auth@example.com", "password123", "USER")` -> `new CreateUserRequest("authuser", "auth@example.com", "password123", Role.USER)`
- Line 61: same pattern for `"authuser2"`
- Line 72: same pattern for `"flowuser"`

- [ ] **Step 2: Update SecurityConfigTest**

In `SecurityConfigTest.java`:

Add import:
```java
import ch.furchert.homelab.auth.entity.Role;
```

Update all `CreateUserRequest` calls:
- Line 51: `new CreateUserRequest("normaluser", "normal@example.com", "password123", "USER")` -> `new CreateUserRequest("normaluser", "normal@example.com", "password123", Role.USER)`
- Line 63: `new CreateUserRequest("adminuser", "admin@example.com", "password123", "ADMIN")` -> `new CreateUserRequest("adminuser", "admin@example.com", "password123", Role.ADMIN)`

- [ ] **Step 3: Run integration tests**

Run:
```bash
./mvnw test -pl . -Dtest="*IntegrationTest,*SecurityConfigTest,AuthServiceApplicationTests" -q 2>&1 | tail -30
```
Expected: All integration tests pass (requires Docker running for Testcontainers).

- [ ] **Step 4: Commit**

```
test: update integration tests for Role enum
```

---

### Task 10: Fix K8s deployment — add DB URL, startup probe, comments

**Files:**
- Modify: `k8s/deployment.yaml`

- [ ] **Step 1: Update deployment.yaml**

In `k8s/deployment.yaml`:

Change the image line (line 22) to add a comment:
```yaml
          # Image tag is substituted by CI/CD pipeline with the git commit SHA
          image: ghcr.io/doemefu/homelab-auth-service:<SHA>
```

Add `SPRING_DATASOURCE_URL` to the env section (after the `DB_PASSWORD` block, before `APP_JWT_PRIVATE_KEY`):
```yaml
            # Adjust to your in-cluster PostgreSQL service name
            - name: SPRING_DATASOURCE_URL
              value: "jdbc:postgresql://postgres-service:5432/homelabdb"
```

Add a startup probe after the readinessProbe block (after line 64):
```yaml
          startupProbe:
            httpGet:
              path: /actuator/health
              port: 8080
            periodSeconds: 2
            failureThreshold: 30
```

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('k8s/deployment.yaml'))" && echo "YAML valid"
```
Expected: "YAML valid"

- [ ] **Step 3: Commit**

```
fix: add DB URL, startup probe, and documentation comments to K8s deployment
```

---

### Task 11: Run full test suite and verify

- [ ] **Step 1: Run full build with tests**

Run:
```bash
./mvnw verify -q 2>&1 | tail -30
```
Expected: BUILD SUCCESS with all tests passing.

- [ ] **Step 2: If any tests fail, fix and re-run**

Diagnose failures from the output, fix the specific issue, and re-run.

- [ ] **Step 3: Final commit if any fixups were needed**

```
fix: address test failures from review findings implementation
```
