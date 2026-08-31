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

## 2026-08-21 — Handoff refresh and feature roadmap — READY FOR OWNER REVIEW

### Intent

- Record the maintainer's assessment that the platform is well tested in
  practice (manual/functional; no automated in-repo suite yet).
- Capture a Proposed Feature Roadmap of substantial, non-bug-fix next builds
  so a future session can pick one up cold.
- Reconcile this branch with the concurrent `main` update that introduced the
  `patch.md` ledger and the Sophos-poller / rule-state decisions.

### Files Changed

- `AI_HANDOFF.md`: reworded Current Status / Architecture / Known Issues to the
  well-tested framing; added the Proposed Feature Roadmap (alert triage
  lifecycle, Sigma rule ingestion, GeoIP + impossible-travel, visual analytics
  overview); refreshed Completed / In Progress / Recommended Next Step /
  Last Verified. Merged with `main` (Sophos + patch.md + rule-state content
  preserved).
- `patch.md`: this entry.
- `AGENTS.md`: taken from `main` via merge (no local edits).

### Behavior and Decisions

- No runtime behavior changed; documentation-only session.
- Well-tested status is recorded as the maintainer's assessment, not an
  independently verified claim; the Sophos poller's production run is preserved
  from `main`.
- Git commit/push/merge performed at the owner's explicit request this session.

### Validation

- Merge conflict resolved with zero remaining conflict markers; only markdown
  files involved (`AI_HANDOFF.md`, `AGENTS.md`, `patch.md`).

### Deployment / Migration

- None; documentation-only change.

### Remaining Work

- Implement a Proposed Feature Roadmap item (suggested: alert triage lifecycle).

## 2026-08-28 — Portable Sophos poller integration bundle — READY FOR OWNER REVIEW

### Intent

- Package the production-verified Sophos Central polling flow for reuse by a
  second SIEM using the same callback contract and `api_pollers` schema.
- Provide a separate integration and operational-safety guide without placing
  credentials or production data in version control.

### Files Changed

- `integrations/__init__.py`: integration-bundle namespace.
- `integrations/sophos_poller_bundle/api_poller.py`: portable poller snapshot.
- `integrations/sophos_poller_bundle/__init__.py`: exports `PollerManager`.
- `integrations/sophos_poller_bundle/schema.sqlite.sql`: matching SQLite state
  schema.
- `integrations/sophos_poller_bundle/schema.postgresql.sql`: matching
  PostgreSQL state schema.
- `integrations/sophos_poller_bundle/sophos-poller.example.json`: safe Sophos
  configuration with placeholders and no secret.
- `integrations/sophos_poller_bundle/integration_example.py`: callback adapter
  skeleton that refuses to advance the cursor until durable delivery is
  implemented.
- `integrations/sophos_poller_bundle/test_bundle.py`: offline mocked tests.
- `integrations/sophos_poller_bundle/INTEGRATION.md`: integration steps,
  callback/schema contract, and operational cautions.
- `AI_HANDOFF.md`: records the portable bundle and transfer contract.
- `patch.md`: this entry.

### Behavior and Decisions

- The production root `api_poller.py` and running mini-SIEM flow were not
  changed.
- The portable copy preserves OAuth2, Bearer Whoami, regional host discovery,
  automatic tenant header, cursor, and callback behavior.
- The portable copy uses the officially documented initial query parameter
  `from_date`; the root production copy still uses its existing established
  cursor path.
- Cursor persistence remains after successful batch ingestion. The target SIEM
  must deduplicate on `(connector, Sophos event id)` because a crash or partial
  batch failure can replay events.
- No Git operation was performed.

### Validation

- Offline mocked Sophos flow: 2 tests passed, 0 failed.
- Verified token, Bearer Whoami, regional events URL, automatic tenant header,
  cursor progression, and first-run `from_date` construction.
- Example JSON parsed successfully.
- Tests made no external HTTP requests and used no production credentials.

### Deployment / Migration

- Copy the entire `integrations/sophos_poller_bundle/` directory to the target
  SIEM and follow `INTEGRATION.md`.
- Apply one matching schema and implement all three callbacks before enabling
  the poller.
- Store the client secret outside the bundle and verify durable ingest plus
  event-ID deduplication before allowing cursor advancement.

### Remaining Work

- Implement the target SIEM's concrete `deliver_to_siem()` adapter.
- Optionally derive token refresh from the OAuth response `expires_in` and add
  exponential backoff/graceful manager shutdown in a future revision.

## 2026-08-31 — CentOS/RHEL two-service deployment hardening — IMPLEMENTED

### Intent

- Fix deployment failures observed while installing the refactored mini-SIEM
  under `/opt/mini_siem` on an SELinux-Enforcing CentOS/RHEL-family host.
- Make the documented privilege split unambiguous: only the syslog listener is
  root for TCP/UDP 514; the Waitress dashboard and API pollers run as a normal
  user.

### Files Changed

- `install-services.sh`: prefer project `.venv` Python, validate Flask+Waitress,
  repair stale `/opt` `user_home_t` labels with `restorecon`, improve startup
  verification/troubleshooting output, retain shared SQLite group semantics.
- `README.md`: make the two-service installer the recommended production path;
  document CentOS/RHEL SELinux `203/EXEC` diagnosis; document SQLite whole-file
  migration including poller/app-config state; mark combined service legacy.
- `AI_HANDOFF.md`: record the deployment behavior and troubleshooting lesson.
- all `*.sh`: normalized to Unix LF line endings to prevent `/usr/bin/env:
  bash\\r: No such file or directory` after Linux deployment.

### Behavior and Decisions

- Core SIEM runtime behavior, poller flow, rule state, database schema, routes,
  and detection logic are unchanged.
- The installer does not disable SELinux and does not set global Python
  capabilities. Under `/opt` it repairs only a detected stale `user_home_t`
  label using the platform's default `restorecon` policy.
- The installer still runs `listener.py` as root because it binds port 514,
  while `dashboard.py` runs as the selected non-root account.

### Validation

- `bash -n` passed for every shell script after LF normalization.
- Installer static inspection confirms project `.venv` preference, Flask +
  Waitress import check, SELinux Enforcing/user_home_t detection, `restorecon`
  path, two generated systemd units, and post-install port/status guidance.
- No live systemd/SELinux service launch was performed in the packaging
  environment; the fix is based on the captured CentOS/RHEL deployment failure
  (`status=203/EXEC`, `/opt/mini_siem` labeled `user_home_t`) and subsequent
  successful relabel to `usr_t`.

### Deployment / Migration

- Recommended install: `python3 -m venv .venv`, install `requirements.txt`, then
  `sudo ./install-services.sh <dashboard-user>`.
- Existing SQLite installations migrate by carrying the complete cleanly-closed
  `siem.db`; do not migrate poller/app-config tables separately and do not
  blindly copy stale `-wal`/`-shm` files.

## 2026-08-31 — Dedicated `siem` service account — IMPLEMENTED

### Intent

- Remove the production service dependency on a maintainer/login account such
  as `matt`.
- Make the privilege model deterministic: only the syslog listener is root;
  the Waitress dashboard and API pollers always run as a dedicated non-login
  service account.

### Files Changed

- `install-services.sh`: automatically creates/validates `minisiem` plus the
  non-login system account `siem`; removes the username/UID installer argument;
  runs the dashboard unit as `siem:minisiem`; creates `/var/lib/mini-siem` as
  the service home; adds preflight execution/write checks; narrows shared write
  setup to the project root and runtime SQLite/config/backup state rather than
  recursively making the code/venv group-writable.
- `README.md`: documents the dedicated service-account model and changes the
  canonical install command to `sudo ./install-services.sh`.
- `AI_HANDOFF.md`: records the new deployment identity and preflight behavior.

### Behavior and Decisions

- `mini-siem-listener`: `User=root`, `Group=minisiem`, TCP/UDP 514.
- `mini-siem-dashboard`: `User=siem`, `Group=minisiem`, Waitress 8080 plus API
  pollers.
- `siem` is a system account with `nologin` (or `/bin/false` fallback), not an
  interactive user. Existing interactive accounts named `siem` are rejected
  rather than silently repurposed.
- `uninstall` removes the systemd units but intentionally leaves the database,
  shared group, and service account untouched to avoid destructive identity or
  data changes.
- Core SIEM routes, detection behavior, poller flow, and DB schema are unchanged.

### Validation

- `bash -n` passes for every shell script; all `*.sh` files are Unix LF with no
  CRLF line endings.
- `python3 -m compileall -q .` passes.
- `security_static_scan.py` reports 0 findings (HIGH=0, MED=0, LOW=0, INFO=0).
- Installer static checks confirm no `DASH_USER`/`SUDO_USER` dependency remains,
  the dashboard unit uses `User=siem`, the listener remains `User=root`, and
  service-account execution/write preflights run before unit installation.
- Full live `useradd`/systemd/SELinux execution remains environment-dependent;
  the installer preserves the previously added CentOS/RHEL `restorecon` logic.
