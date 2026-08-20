# Mini SIEM Patch Ledger

## Purpose

This file is the persistent implementation ledger for AI-assisted development.
It complements, but does not replace, Git history:

- `AI_HANDOFF.md` describes the current architecture, operational state,
  important design decisions, known gaps, and recommended next task.
- `patch.md` records concrete code/documentation changes, validation results,
  deployment notes, and the ordered implementation slices still pending.
- Git synchronization, staging, commits, tags, and pushes are performed by the
  repository owner, not by the AI unless the owner explicitly changes that rule.

Every AI making a material change must update this file in the same work session.
Do not record credentials, API keys, private URLs, private keys, or production
event contents here.

## Status Labels

- `PLANNED` — agreed scope; implementation has not started.
- `IN PROGRESS` — implementation started but is not fully validated.
- `READY FOR OWNER REVIEW` — implementation and local validation completed;
  Git actions remain with the owner.
- `DEPLOYED / USER VERIFIED` — owner confirms the change is running in the
  target environment.
- `DEFERRED` — intentionally postponed.
- `DESIGN / NO CHANGE` — reviewed behavior is intentional and should not be
  treated as a defect.

## Current Baseline

### Security hardening — READY FOR OWNER REVIEW

Implemented:

- Per-session CSRF tokens for authenticated state-changing browser requests.
- `X-CSRF-Token` injection for same-origin UI `fetch` calls.
- Optional exact-origin enforcement through
  `MINISIEM_ALLOWED_ORIGIN` / `MINISIEM_ALLOWED_ORIGINS`.
- Intentional CSRF exemptions for SAML ACS and API-key ingestion.
- In-memory local-login throttling:
  - 5 failures per source-IP/username pair within 5 minutes.
  - 20 failures per source IP within 10 minutes.
  - HTTP 429 with `Retry-After` when limited.
- Dynamic security coverage for CSRF and login throttling.

Validation previously completed:

- Python AST parsing: 22 files passed.
- JavaScript syntax: `static/csrf.js` passed.
- Dynamic security scan: 33 passed, 0 failed.
- Static security scan: 19 modules scanned; 12 advisory dynamic-SQL pattern
  findings remain manually reviewed with no confirmed SQL injection.

Deployment note:

- CSRF requires `dashboard.py`, `static/csrf.js`, and the updated templates to
  be deployed together.
- The allowed origin must match the browser-visible origin, not `0.0.0.0`.

### Sophos Central poller — DEPLOYED / USER VERIFIED

- The `oauth2_sophos` integration is implemented and continuously operational.
- Production evidence supplied by the owner: 4,739 real Sophos API events
  collected from 2026-08-05 through 2026-08-20.
- Preserve the verified flow unless an explicit, separately tested change is
  requested:
  1. Exchange client ID/secret for a JWT with scope `token`.
  2. Pass the JWT as a Bearer token to Sophos Whoami.
  3. Discover tenant ID and regional API host.
  4. Request path-only `/siem/v1/events` with `X-Tenant-ID`.
  5. Refresh the in-memory access token before assumed expiry.
  6. Persist the event cursor in the database.

### Live-rule state — DESIGN / NO CHANGE

- Sliding-window state for live rules is intentionally memory-only.
- Listener restart resets incomplete live-rule windows.
- Stored logs and generated alerts remain persistent.
- Historical detection across restarts belongs to database-backed correlation
  playbooks.

## Planned Implementation Slices

### Slice 0 — Repository/runtime secret hygiene — PLANNED

Scope:

- Ignore runtime DB, WAL/SHM, backups, logs, environments, and local secret
  configuration.
- Add safe `auth-config.example.json` and `db-config.example.json` templates.
- Preserve a workable first-run path when live config files do not exist.
- Add a repeatable accidental-file/high-confidence-secret check.

Acceptance:

- No real credentials or runtime databases in the publish set.
- Example configuration contains placeholders only.
- Application starts with documented defaults or copied local configuration.

### Slice 1 — HTTP API-key ingestion authentication — PLANNED

Confirmed issue:

- The global browser login guard currently blocks unauthenticated
  `/api/ingest` requests before the endpoint can validate its API key.

Scope:

- Exempt only `api_ingest` from browser-session authentication.
- Retain endpoint API-key validation and CSRF exemption.
- Add tests for missing, invalid, and valid API keys without a browser session.

### Slice 2 — HTTP request size limits — PLANNED

Scope:

- Add configurable Flask request-size limit.
- Limit individual log size and text-ingest line count.
- Preserve the existing 1,000-event JSON batch limit.
- Return HTTP 413 for oversized payloads.

### Slice 3 — PostgreSQL search compatibility — PLANNED

Confirmed issue:

- Dashboard keyword search always references SQLite `logs_fts`; PostgreSQL does
  not create that virtual table.

Scope:

- Keep SQLite FTS5 behavior unchanged.
- Add PostgreSQL-safe message search, initially via parameterized `ILIKE`.
- Preserve include/exclude semantics and SQL-injection resistance.

### Slice 4 — PostgreSQL full-text/integration baseline — PLANNED

Scope:

- Validate the complete schema and dashboard against a real PostgreSQL server.
- Add PostgreSQL-native `tsvector`/GIN search if warranted by measured load.
- Record representative ingestion and search performance.

### Slice 5 — Data retention — PLANNED

Scope:

- Add disabled-by-default retention (`retention_days = 0`).
- Provide dry-run counts and batched deletion.
- Clean dependent fields/matches/FTS data without orphaning rows.
- Keep SQLite and PostgreSQL maintenance paths separate.

### Slice 6 — Poller event idempotency — PLANNED

Scope:

- Add connector-scoped external event IDs for events that provide stable IDs.
- Prevent duplicates if a poller process stops after partial ingestion but
  before cursor persistence.
- Do not alter the verified Sophos authentication, Whoami, regional routing,
  token-refresh, or cursor flow.

### Slice 7 — IOC feed download limits — PLANNED

Scope:

- Replace unlimited feed reads with bounded/chunked downloads.
- Enforce a configurable maximum response size.
- Preserve existing IOC data when a refresh is rejected or fails.

### Slice 8 — SSO least-privilege roles — PLANNED

Scope:

- Default new OAuth/SAML users to `viewer`, not `admin`.
- Load the persisted role at login.
- Retain an explicit local break-glass administrator.
- Add IdP claim/group mapping only as a separate optional step.

### Slice 9 — Outbound URL/SSRF policy — PLANNED

Scope:

- Apply connector-specific URL policy rather than blocking all private hosts.
- Preserve local Ollama and verified Sophos endpoints.
- Block unsupported schemes, link-local/cloud-metadata destinations, unsafe
  redirects, and disallowed resolved addresses.

### Slice 10 — Automated regression suite/CI — PLANNED

Scope:

- Add tests for parsing, DB initialization, authentication, CSRF, throttling,
  API-key ingestion, PostgreSQL query generation, retention, idempotency, and
  URL validation.
- Use temporary databases and synthetic data only.
- Never contact production Sophos or external providers from CI.

## Recommended Order

1. Slice 0 — repository/runtime secret hygiene.
2. Slice 1 — HTTP API-key ingestion authentication.
3. Slice 2 — request limits.
4. Slice 10 subset — regression tests for Slices 0–2.
5. Slice 3 — PostgreSQL compatibility.
6. Slice 4 — real PostgreSQL integration baseline.
7. Slices 5–7 — retention, idempotency, feed limits.
8. Slices 8–9 — optional SSO/SSRF hardening.
9. Complete Slice 10.

## Patch Entry Template

Copy this section for every material change:

```markdown
## YYYY-MM-DD — Short change title — STATUS

### Intent
- What problem or requirement this change addresses.

### Files Changed
- `path`: concise description.

### Behavior and Decisions
- Important implementation details and intentional trade-offs.

### Validation
- Exact tests/checks run and their results.

### Deployment / Migration
- Required config, schema, restart, ordering, or rollback notes.

### Remaining Work
- Follow-ups, known limitations, or `None`.
```

## 2026-08-20 — Patch ledger and AI handover process — READY FOR OWNER REVIEW

### Intent

- Establish `patch.md` as the durable implementation/change ledger requested by
  the repository owner.
- Prevent future AI sessions from treating intentional live-rule and Sophos
  behavior as defects.

### Files Changed

- `patch.md`: created baseline, planned slices, validation history, and entry
  template.
- `AGENTS.md`: requires reading and updating `patch.md`.
- `AI_HANDOFF.md`: documents the division of responsibility between the current
  state handoff and patch ledger.

### Behavior and Decisions

- No runtime behavior changed.
- No Git synchronization, staging, commit, or push was performed.

### Validation

- Documentation structure and cross-references reviewed locally.

### Deployment / Migration

- None; documentation-only change.

### Remaining Work

- Repository owner handles Git review and synchronization.
