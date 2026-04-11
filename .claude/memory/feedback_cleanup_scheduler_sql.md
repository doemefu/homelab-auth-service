---
name: TokenCleanupScheduler SQL WHERE clause pattern
description: COALESCE-to-epoch inside GREATEST matches all-NULL rows immediately; always guard with IS NOT NULL when intending a separate branch for all-NULL rows
type: feedback
---

When writing a DELETE WHERE clause that has two intended cases — (a) at least one expiry is set and all are past, and (b) no expiry is set and the row is old — do NOT use `COALESCE(col, to_timestamp(0))` inside `GREATEST` without guarding for the all-NULL case.

**Why:** `GREATEST(COALESCE(a, epoch), COALESCE(b, epoch), ...) < NOW()` evaluates to `epoch < NOW()` which is always true when all columns are NULL. This collapses the two intended cases into one, deleting in-progress authorization flows immediately instead of after the 24h grace period.

**How to apply:** Guard the expiry branch with an explicit IS NOT NULL check:
```sql
WHERE (
    (col_a IS NOT NULL OR col_b IS NOT NULL OR ...)
    AND GREATEST(COALESCE(col_a, to_timestamp(0)), ...) < NOW()
)
OR (
    col_a IS NULL AND col_b IS NULL AND ...
    AND issued_at < NOW() - INTERVAL '24 hours'
)
```
