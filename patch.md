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

## 2026-09-01 — Warning-triggered AI source context — SUPERSEDED by corrected trigger/related contract below

- Generic severity alerts now trigger on `warning`, `error`, `critical`, `alert`, and `emergency` events.
- The generated alert preserves the triggering event's actual normalized severity instead of labeling every severity-triggered alert as `critical`.
- `notice` and `informational` events do not trigger LLM triage by themselves; when the same `source_ip` has a warning-or-higher alert, existing AI context gathering includes the source's recent events regardless of severity (up to `MAX_CONTEXT_EVENTS`, currently 40).
- Restored the protected Sophos SIEM v1 first-request query parameter to `from_date`; the regression test remains unchanged.
- GitHub Actions token permissions are explicitly read-only (`contents: read`).

## 2026-09-01 — AI source-context trigger bypasses ordinary minimum severity — SUPERSEDED by corrected trigger/related contract below
- `high_severity_event` warning-or-higher source-context alerts now bypass `ai_auto_triage_min_severity`.
- Setting the UI threshold to `error` or `critical` no longer suppresses a warning source-context incident; the LLM still receives same-source notice/informational events as evidence.
- The minimum-severity setting still applies to ordinary/non-source-context alerts.


## 2026-09-01 — Corrected NXLog trigger / cross-source related evidence contract

### Intent
- Separate *what starts an investigation* from *what evidence the LLM receives*.
- Make NXLog Windows warning/error events useful triggers without making firewall warning/error inherit the same trigger policy.
- Once an alert is legitimately triggered, correlate the trigger IP across source and destination roles and across products.

### Files Changed
- `rules.py`: adds narrow `NxlogSeverityRule`; restores the generic non-NXLog severity trigger to its original `critical`/`alert`/`emergency` boundary and prevents duplicate generic firing for NXLog Windows JSON.
- `ai_worker.py`: only the dedicated `nxlog_severity_event` bypasses the ordinary AI minimum-severity setting.
- `ai_soc.py`: resolves an investigation IP and gathers bounded cross-source related evidence from `source_ip`, `destination`, `peer_ip`, and indexed source/destination fields such as Sophos `endpoint_ip`; no related-evidence severity filter is applied.
- `listener.py`: explicitly maps Windows EventID 4738 to `notice`.
- `tests/test_warning_ai_context.py`: regression coverage for trigger separation and cross-source/source+destination related evidence.
- `templates/ai.html`, `README.md`, `AI_HANDOFF.md`: document the corrected contract.

### Behavior
- NXLog Windows `warning` and above -> `nxlog_severity_event` trigger.
- NXLog `notice`/`informational` -> no standalone trigger, but eligible as related evidence.
- Firewall `warning`/`error` -> no NXLog trigger. Existing firewall rules remain unchanged; the original generic non-NXLog critical/alert/emergency trigger remains.
- Related evidence after a trigger may include NXLog, firewall, Sophos/API, and other logs, including cases where the trigger IP is the destination rather than the source.
- `ai_auto_triage_min_severity=error|critical` does not suppress an NXLog warning trigger; it continues to apply to ordinary alerts.

### Validation
- Dedicated trigger/related regression suite: 10 passed.
- Core DB/SQL/Sophos plus trigger/related tests: 18 passed.
- `python3 -m compileall -q .`: passed.
- `security_static_scan.py`: 0 findings.
- Full pytest collection is blocked in the packaging environment because Flask is not installed; CI installs `requirements-dev.txt` and runs the full suite.

## 2026-09-01 — Scheduled playbook alert/ticket behavior documented — DOCUMENTATION ONLY

### Scope
- Documentation-only correction; no runtime code, schema, worker, alert, AI, or ticket behavior changed.
- `README.md` and `AI_HANDOFF.md` now distinguish the current implementation from the intended playbook automation contract.

### Current Runtime Behavior
- Scheduled playbook runs persist findings as reports.
- `ReportScheduler` is currently started without an `on_report` callback.
- Therefore scheduled findings do not currently create alerts.
- Because no alert is created, the ticket worker has nothing to dispatch for that scheduled finding.
- LLM triage is not required for ticket creation; the ticket worker consumes qualifying rows from the `alerts` table directly.

### Intended Future Contract
- Scheduled playbook finding -> alert.
- The playbook-generated alert should skip LLM triage by default.
- The alert should still flow to the existing ticket worker and create a ticket when it meets the configured ticket minimum severity.
- This contract remains **planned/not implemented** until the scheduler is explicitly wired to create the alert.


## 2026-09-01 — Progressive related-investigation profiles documented — DOCUMENTATION ONLY (HISTORICAL; SUPERSEDED)

### Scope

- Added `DEVELOPMENT.md`, `OPERATION.md`, and `PRODUCT.md` as canonical design/operations/product documentation.
- Updated `README.md` navigation and `AI_HANDOFF.md` handoff state.
- No Python, shell, schema, service, rule, AI worker, playbook, ticket, or runtime behavior changed.

### Planned Contract

- Trigger policy remains source-specific and separate from related-evidence retrieval.
- Related evidence remains cross-source, cross-severity, and source/destination/entity aware.
- Investigation runs Short first and calls the LLM with Short evidence only.
- Medium is retrieved/called only when Short finds no suspicious/relevant evidence or reports insufficient evidence.
- Long is retrieved/called only when Medium also finds no suspicious/relevant evidence or remains insufficient.
- Expansion stops as soon as suspicious/relevant evidence is found.
- Medium is generally about 3x the Short investigation scope; Long is generally about 10x, with investigation-specific asymmetric defaults.
- Long-profile evidence must be deduplicated/aggregated before LLM submission.

### Runtime Status at the time of this documentation-only entry

- At this point in history, the Short -> Medium -> Long state machine was not yet implemented.
- This status is superseded by the later **Progressive AI investigation profiles implemented** entry below.

## 2026-09-01 — Progressive AI investigation profiles implemented

Runtime change (not documentation-only): added `investigation_profiles.py`; replaced generic latest-N AI related retrieval with profile-bounded Short/Medium/Long retrieval; added application-controlled LLM decisions (`SUSPICIOUS`, `NO_SUSPICIOUS`, `INSUFFICIENT`); added sequential escalation and stop rules; added Long repeated-pattern reduction/summaries; preserved NXLog/firewall trigger separation and cross-source related evidence. Added regression tests for profile classification, time-window expansion, escalation sequencing, missing-marker fail-open behavior, and Long reduction. Manual `/api/ai/triage` and background auto-triage now share the same state-machine implementation. Verification: 30 non-Flask tests passed, `compileall` passed, static security scan 0 findings, shell syntax/LF checks passed; Flask-dependent route/import tests could not be collected in the packaging environment because Flask was unavailable and pip had no network access.


## 2026-09-01 — Progressive AI investigation runtime hardened

### Runtime behavior
- Short is always the first LLM investigation stage.
- `SUSPICIOUS` stops widening immediately.
- `NO_SUSPICIOUS` or `INSUFFICIENT` widens Short -> Medium -> Long sequentially; Long is terminal.
- Missing/invalid decision markers fail open as `INSUFFICIENT` so the investigation widens rather than stopping prematurely.
- Profile windows are investigation-specific and centered on linked trigger-event time when available, with `alert.created_at` as fallback.
- Related evidence remains cross-source, cross-severity, and source/destination/peer/indexed-endpoint aware.
- Long collapses repeated exact event shapes to representative first/closest/last rows and adds bounded pattern summaries.
- Existing NXLog warning+ trigger behavior and independent firewall trigger behavior are preserved.

### Validation
- Progressive/NXLog/related/profile regression: 21 passed.
- Additional DB/SQL/Sophos tests that do not import Flask pass; Flask-dependent full collection is not runnable in this packaging environment because Flask is absent.
- `python -m compileall -q .`: passed.
- `python security_static_scan.py`: 0 findings.

## 2026-09-11 — Fix fresh-DB init crash and broken log-search test fixture — READY FOR OWNER REVIEW

### Intent

- Restore a working fresh-database bootstrap (a new install could not initialize
  its schema) and unblock the log-search regression test.
- Scope was limited to concrete, shipped-code defects; four in-progress feature
  areas (ingest perf pipeline, FTS text search, evidence archive, timeline/
  live-refresh UI) were intentionally left untouched to avoid colliding with
  active development. Their tests remain red pending implementation.

### Files Changed

- `db.py`:
  - `ensure_schema_baseline` now records every already-applied migration via a
    per-row `conn.execute` loop. The previous `conn.executemany(...)` call was a
    silent no-op: the `Connection` wrapper exposes `execute()` but not
    `executemany()`, so the call raised `AttributeError`, which the surrounding
    bare `except Exception:` swallowed. As a result a fresh SQLite database
    recorded no baseline, replayed all migrations, and crashed on the first
    `ALTER TABLE alerts ADD COLUMN ai_status` (already present in the base
    schema): `sqlite3.OperationalError: duplicate column name: ai_status`.
  - Added `fts5_available(conn)` helper (detects the SQLite FTS5 compile option;
    always False on postgres; probe errors degrade to False).
- `tests/test_log_search_logic.py`: the id=4 seed row supplied 9 values for a
  10-column `INSERT` (missing `app_name`), raising
  `sqlite3.ProgrammingError: Incorrect number of bindings supplied`. Added the
  missing value.

### Behavior and Decisions

- Fresh-DB initialization is fixed and idempotent (verified by initializing a
  new database twice with no error).
- No runtime behavior changed beyond correct schema bootstrap; the missing
  migration baseline previously only "worked" on databases that predated the
  duplicated columns.

### Validation

- Fresh `db.initialize()` on a new SQLite path (run twice): OK.
- Core test suite (excluding the four unimplemented-feature areas): 42 passed.
- `python -m compileall -q .`: passed.
- `python security_static_scan.py`: 0 findings (25 files).
- `import dashboard, siem, archive, maintenance`: OK.

### Deployment / Migration

- None. Existing databases already carrying the columns are unaffected; the fix
  only corrects the fresh-install path.

### Remaining Work

- CI (`pytest -q`) stays red until the four in-progress features land:
  ingest perf pipeline (`Storage.insert_log(fields=...)`, configurable
  `busy_timeout`, `IngestPipeline`), FTS text search (`db.text_search_*`,
  dashboard FTS-availability gating and OR-mode search), evidence archive
  (`archive` registration), and the timeline/live-refresh template markup.

## 2026-09-11 — Migration-safe admin bootstrap + PostgreSQL-aware installer — READY FOR OWNER REVIEW

### Intent

- Protect an existing admin identity during a SQLite -> PostgreSQL migration.
- Stop the class of deploy failure where a code pull adds a dependency
  (e.g. `waitress`) or switches backend but the service environment is not
  re-provisioned, causing the dashboard to crash-loop or silently fall back to
  SQLite.

### Files Changed

- `db.py`: `ensure_admin_bootstrap_safe()` was dead code and, as written, used a
  raw psycopg2 cursor (`conn.cursor()`/`%s`) the `Connection` wrapper does not
  provide. Rewritten to be backend-portable via `conn.execute` (`?` -> `%s`),
  returning whether the bootstrap admin exists; never modifies data.
- `auth.py`: `seed_default_admin()` now calls `ensure_admin_bootstrap_safe()`
  first and skips seeding when an admin already exists, so a migrated admin's
  real credentials/`must_change_password` flag are never overwritten by the
  admin/admin re-seed. Empty-table behavior is unchanged.
- `tests/test_admin_bootstrap.py` (new): verifies default admin is seeded
  (forced password change) on an empty DB, and that an existing admin is
  preserved untouched.
- `install-services.sh`: detects the configured backend from `db-config.json`;
  when PostgreSQL, provisions `psycopg2-binary` (an optional driver not in
  requirements.txt) and includes it in the venv import health checks; verifies
  the service account actually resolves the postgres backend (readable
  `db-config.json`) and fails loudly instead of silently using SQLite; sets
  `db-config.json`/`auth-config.json` to `640` (group-readable, not
  world-readable) since they carry secrets.
- `OPERATION.md`: added an "Upgrading a deployed instance" section — after any
  `git pull`, re-run `install-services.sh` before restarting; documents the
  psycopg2/`db-config.json` readability requirements and the SQLite-fallback
  symptom.

### Behavior and Decisions

- The dashboard `waitress` crash on the owner's host was root-caused to a venv
  that was not re-provisioned after the pull (not the installer). Re-running
  `install-services.sh` fixes it; the installer is now also postgres-aware.
- The separate config-tracking issue (`db-config.json`/`auth-config.json`
  committed to git, so a pull overwrote the host's postgres config) was left as
  operator-managed for now, per owner decision.

### Validation

- `bash -n install-services.sh`: OK.
- New admin-bootstrap tests: 2 passed. Core suite (excluding the four
  in-progress feature areas): 44 passed.
- `python -m compileall -q .`: passed. `security_static_scan.py`: 0 findings.
- Fresh SQLite `db.initialize()`: OK.

### Deployment / Migration

- On the host: after pulling, run `sudo ./install-services.sh`; for postgres,
  ensure `db-config.json` is readable by the service account (installer now
  enforces `640` and fails if the backend does not resolve).

### Remaining Work

- CI (`pytest -q`) remains red pending the four in-progress feature areas
  (ingest perf pipeline, FTS text search, evidence archive, timeline UI).
