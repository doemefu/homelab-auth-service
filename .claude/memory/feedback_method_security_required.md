---
name: method-security-required
description: '@PreAuthorize is silently ignored without @EnableMethodSecurity. AuthorizationDeniedException must be mapped to 403 in GlobalExceptionHandler or generic 500 kicks in.'
metadata:
  type: feedback
---

`@PreAuthorize` on a Spring controller method is **silently ignored** unless `@EnableMethodSecurity` is present on a `@Configuration` class (default `prePostEnabled=true` since SS6). The endpoint will reach the controller as long as the filter chain authenticates the request, regardless of authority requirements.

**Why:** Method security is opt-in to keep the spring-security-config dependency surface minimal. The annotation is only an AOP marker — without `@EnableMethodSecurity` the post-processor that wires the security advisor never runs.

**How to apply:**
- Whenever introducing `@PreAuthorize`, verify (or add) `@EnableMethodSecurity` on `SecurityConfig`.
- In Spring Security 7+, denied checks throw `org.springframework.security.authorization.AuthorizationDeniedException` (NOT the legacy `AccessDeniedException`). If the project has a `@RestControllerAdvice` with `@ExceptionHandler(Exception.class)` catch-all, it will return 500 instead of 403. Always register an explicit handler that returns 403 for both `AuthorizationDeniedException` AND `AccessDeniedException`.
- Add a unit test that calls the endpoint with an insufficient authority and asserts `403` — without that test, both regressions are invisible.

Related: [[feedback_oidc_secret_prefix]] (similar silent-failure pattern with DelegatingPasswordEncoder).
