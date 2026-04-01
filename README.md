### auth-service

**Domain:** Identity and access management.

**Responsibilities:**
- User CRUD (create, read, update, delete, password reset)
- JWT token issuance (`POST /auth/login` -> signed JWT)
- JWT token refresh (`POST /auth/refresh`)
- JWKS endpoint (`GET /auth/jwks`) for other services to validate tokens
- Role-based access control (USER, ADMIN)

**Does NOT:**
- Talk to MQTT, InfluxDB, or any IoT concerns
- Call other services at runtime (self-contained)

**Database:** PostgreSQL — `users` table (owns it)

**Key design decision:** Uses **jjwt library with RSA key pair** instead of Spring Authorization Server. The RSA public key is exposed via a JWKS endpoint. Other services validate tokens locally using the public key — no runtime dependency on auth-service for token validation.
