---
name: Jackson 3 package group in Spring Boot 4
description: Project uses tools.jackson (Jackson 3), not com.fasterxml.jackson (Jackson 2) — verify all Jackson imports
type: feedback
---

Spring Boot 4 bundles Jackson 3, which moved to the `tools.jackson` package group.

**Why:** Mixing `com.fasterxml.jackson.*` (Jackson 2) and `tools.jackson.*` (Jackson 3) imports causes compilation failures because both may be on the classpath but are incompatible types.

**How to apply:**
- `ObjectMapper` → `tools.jackson.databind.ObjectMapper`
- `JsonNode` → `tools.jackson.databind.JsonNode`
- Always inject `@Autowired ObjectMapper objectMapper` in tests rather than `new ObjectMapper()` — the Spring-managed bean is correctly configured.
- When reviewing any code that uses Jackson, grep for `com.fasterxml.jackson` and replace.
