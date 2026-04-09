### Java
- Standard Spring Boot conventions
- Lombok for boilerplate reduction
- Flyway for all database migrations (no `ddl-auto=update` in production)

### Secrets
- Plaintext secrets in git: **forbidden**
- Encrypt via SOPS + age before finishing: `sops -e -i <file>`
- age key lives **outside** the repo