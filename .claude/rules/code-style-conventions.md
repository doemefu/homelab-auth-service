---
paths:
  - "src/**/*.java"
  - "src/main/resources/db/migration/**/*.sql"
  - "src/main/resources/*.yaml"
  - "pom.xml"
  - "k8s/**"
  - "Dockerfile"
---
### Java
- Standard Spring Boot conventions
- Lombok for boilerplate reduction
- Flyway for all database migrations (no `ddl-auto=update` in production)

### Secrets
- Plaintext secrets in git: **forbidden**
- Secrets reach the service as K8s Secrets (`secretKeyRef` / env vars), provisioned by the `infrastructure` repo (SOPS + age live there, not here)
- `src/main/resources/keys/` is gitignored local-dev only; test keys in `src/test/resources/keys/` are tracked and not real credentials
