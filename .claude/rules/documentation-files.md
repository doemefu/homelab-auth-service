# Documentation Files — Purpose & Owner

When making changes, update the relevant file(s) — the `doc-auditor` subagent (Phase 6) identifies what needs updating.

| File              | Audience     | Covers |
|-------------------|--------------|--------|
| `README.md`       | Everyone     | Service overview, API, config, quick start |
| `OPERATIONS.md`   | Operators    | Runbooks, upgrade procedures, backup/restore, troubleshooting |
| `CONTRIBUTING.md` | Contributors | Local dev setup (port-forward), testing, PR process |
| `DEPLOYMENT.md`   | App developers | K8s deployment, secrets, ingress |
| `CHANGELOG.md`    | App users    | Describes changes to prior versions the user is affected by |

**Rule:** Docs are written in parallel with the code change, not after.
