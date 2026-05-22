# Documentation Files — Purpose & Owner

When making changes, update the relevant file(s) — the `doc-auditor` subagent (Phase 6) identifies what needs updating.

| File              | Audience     | Covers |
|-------------------|--------------|--------|
| `README.md`       | Everyone     | Landing page — documentation index, quick start, quick reference |
| `OVERVIEW.md`     | Everyone     | What the service is, context, features, URLs & API summary |
| `INTERFACES.md`   | Integrators  | How external services/clients interact (OIDC, REST, JWKS, device clients) |
| `DEPLOYMENT.md`   | App developers | K8s deployment, secrets, ingress, troubleshooting |
| `CONTRIBUTING.md` | Contributors | Local dev setup (port-forward), testing, PR process |
| `CHANGELOG.md`    | App users    | Describes changes to prior versions the user is affected by |
| `docs/INDEX.md`   | Everyone     | Index of supplementary `docs/` material |
| `docs/DEVELOPMENT.md` | Contributors | Extended development guide |

**Rule:** Docs are written in parallel with the code change, not after.
