---
name: Testcontainers lifecycle in AbstractIntegrationTest
description: Use static initializer for the shared PostgreSQLContainer — NOT @Testcontainers + @Container. The annotation approach stops the container between test classes and breaks integration tests.
type: feedback
---

**Use `static { postgres.start(); }` — do NOT use `@Testcontainers` + `@Container` on the abstract base class.**

**Why:** With `@Testcontainers` on an abstract class and `@Container static` field, JUnit 5's `AfterAllCallback` stops the container after each **concrete subclass** finishes. When `AuthServiceApplicationTests` completes, the container is stopped. `OidcFlowIntegrationTest` then fails to connect (port still registered in `@DynamicPropertySource` but container dead). This causes "Connection refused" errors in all subsequent integration test classes.

The static initializer approach starts the container once during JVM class-loading and keeps it alive for the entire test run. No JUnit 5 lifecycle hooks can stop it between classes.

Copilot PR review flagged the static initializer as a "resource leak" and recommended `@Testcontainers` + `@Container`. This advice was tested and confirmed broken — reverting to static initializer restored CI. Do not follow this Copilot suggestion.

**How to apply:** In `AbstractIntegrationTest`, always keep:
```java
static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17-alpine");
static {
    postgres.start();
}
```
With a comment explaining why `@Testcontainers` + `@Container` must not be used here.
