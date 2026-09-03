# AI Development Handoff

## Project
Mini SIEM

## Objective
Continue development and improvement of the Mini SIEM platform.

## Current Status
The initial source import is intact. Per the maintainer, the platform is well
tested in practice: it has been exercised functionally end-to-end and is
considered stable for its intended use (the Sophos poller, for example, has run
in production — see Known Issues). That testing is primarily manual/functional. A small in-repo pytest regression
baseline and GitHub Actions workflow now protect DB helpers, SQL-composition
helpers, the dashboard/siem import surface, route-map parity, auth/public-route
behavior, and CSRF behavior. Dashboard/Flask-dependent checks still cannot run
in an environment where Flask is unavailable; that remains an environment gap,
not a product defect.

## Architecture Baseline
- `siem.py` is the combined entry point for syslog listeners and the Flask
  dashboard; `listener.py` and `dashboard.py` can also run separately.
- Syslog ingestion supports UDP/TCP, parses RFC3164/RFC5424-style messages,
  stores events through the abstraction in `db.py`, and invokes live rules,
  IOC matching, field indexing, and forwarding.
- SQLite is the default tested backend. PostgreSQL support is implemented but
  still requires validation against a real PostgreSQL instance.
- The dashboard includes local authentication, optional OAuth/SAML, CSRF
  protection, log search, retrospective correlations/playbooks, health and
  audit views, AI triage, API polling, threat-intelligence feeds, API-key
  ingestion, and administration/configuration endpoints.
- The maintainer reports the platform is well tested through hands-on
  functional testing across ingestion, the dashboard, and its feature set.
  This is now partially captured by a deliberately small pytest/CI regression
  suite. Mechanical validation also includes `security_static_scan.py`,
  `security_dynamic_scan.py`, syntax compilation, and manual smoke tests.

- 2026-08-31 refactor/hardening: fixed the missing `db.test_connection()`
  function; replaced Flask/Werkzeug `app.run()` in both entry paths with
  single-process threaded Waitress; split only AI, IOC feeds, DB health/backup,
  users, reports, and ticket routes into `web_blueprints/` while preserving all
  102 path/method route contracts; added request-scoped dashboard DB connection
  reuse plus a bounded thread-safe PostgreSQL connection pool; centralized
  dynamic SQL placeholder/identifier composition in `sql_helpers.py`; and added
  pytest + GitHub Actions regression scaffolding. Static route comparison found
  no missing/extra route contracts. `compileall`, SQLite initialize/connect/
  integrity smoke, and `security_static_scan.py` pass; the static scanner reports
  0 findings. Full Flask/pytest and `security_dynamic_scan.py` remain unexecuted
  in the packaging environment because Flask/pytest are not installed and
  network package installation is unavailable.

## AI Git Workflow

AI may perform normal Git operations:

- `git pull`
- `git add`
- `git commit`
- `git push`

Before pushing:

- Run relevant tests and validation checks.
- Update `AI_HANDOFF.md` with completed work, verification results, and next recommended steps.
- Review `git diff` and `git status`.
- Ensure no secrets, credentials, generated binaries, temporary files, or unrelated changes are included.

Never:

- Force push.
- Rewrite history unless explicitly approved.
- Delete branches or change remotes without approval.

## Multi-Agent Coordination

- GitHub is the source of truth.
- Before starting work, synchronize with the latest repository state.
- Do not assume another AI agent's uncommitted local changes exist.
- Do not modify the same repository concurrently with another AI agent unless the work is isolated by branch.
## Completed
- Existing SIEM source imported and repository initialized.
- Repository exclusions and permanent AI instructions configured.
- Reviewed repository instructions, README, entry points, dependency list,
  configuration defaults, security scanners, and representative SQL flagged by
  the static scanner.
- Established a passing syntax and core-runtime baseline on 2026-08-17.
- 2026-08-21 session: re-read README.md, AGENTS.md, and AI_HANDOFF.md; confirmed
  project purpose, permanent working rules, and current state. Recorded the
  maintainer's assessment that the platform is well tested in practice, and
  captured a Proposed Feature Roadmap of substantial (non-bug-fix) next builds.
  Merged the concurrent `main` update (patch.md ledger, Sophos-poller and
  rule-state decisions) into this branch. No source code was changed this
  session; only handoff/ledger documentation was edited.
- 2026-08-28 session: added a version-controlled, self-contained Sophos poller
  integration bundle under `integrations/sophos_poller_bundle/`. It preserves
  the verified callback/schema contract and includes SQLite/PostgreSQL schema,
  a safe adapter skeleton, credential-free example configuration, integration
  and operational notes, and offline HTTP-mocked tests. The portable copy uses
  Sophos's documented first-run `from_date` query parameter; the production
  root `api_poller.py` was intentionally not changed.

## Test and Review Results (2026-08-17)
- `python3 -m compileall -q .`: PASS (bytecode redirected outside the repo).
- Core temporary-SQLite smoke test: PASS. Verified schema initialization,
  RFC3164 parsing, log insertion, rule processing, field indexing, IOC matching,
  a stored log count, and `secretbox` encrypt/decrypt round-trip.
- `python3 listener.py --help`: PASS.
- `python3 security_static_scan.py --json`: completed successfully; 19 Python
  modules scanned and 12 HIGH pattern findings reported. Manual inspection found
  the flagged SQL to use generated parameter placeholders, fixed internal
  clauses, or allowlisted identifiers. No confirmed SQL injection was identified,
  but these remain advisory findings rather than proof of full security.
- `python3 security_dynamic_scan.py`: NOT RUN to completion; import stopped with
  `No module named 'flask'` (exit 2).
- `python3 siem.py --help` and `python3 dashboard.py --help`: BLOCKED by the same
  missing Flask dependency. The listener CLI does not require Flask and passed.
- No project files or configured `siem.db` were touched by tests; temporary
  databases were used.

## In Progress
- Establishing the Flask/dashboard runtime and security-test baseline in
  environments that have `requirements.txt` installed.
- Selecting the first feature from the Proposed Feature Roadmap to implement.

## Known Issues and Gaps
- The active environment does not have the dependency from `requirements.txt`
  installed, so dashboard imports and the dynamic security scan are unverified.
- OAuth/OIDC and SAML flows have not been tested against live identity providers.
- PostgreSQL has not been tested against a live server.
- The platform is well tested manually/functionally per the maintainer, but
  that coverage is not yet encoded as an automated in-repo unit/integration
  suite, and no CI configuration is present. Codifying the existing manual
  coverage into an automated suite would guard against regressions.
- Live socket ingestion, long-running workers, external AI providers, generic
  API pollers, forwarding targets, and scheduled threat-intelligence retrieval
  were not exercised in this local baseline. The Sophos poller is an exception:
  it is fully implemented and user-confirmed working in production. From
  2026-08-05 through 2026-08-20 it continuously pulled 4,739 real Sophos API
  events. It was not independently revalidated during this local baseline.
- TCP ingestion assumes newline-delimited messages rather than RFC6587
  octet-counted framing.
- Scheduled playbook findings currently stop at the `reports` table. The
  dashboard starts `workers.ReportScheduler(...)` without an `on_report`
  callback, so scheduled findings do not currently raise alerts or create
  tickets. This is a documented implementation gap, not an LLM requirement.
  Intended future contract: scheduled playbook finding -> alert -> ticket
  pipeline (subject to ticket minimum severity), while the playbook-generated
  alert skips LLM triage unless that policy is explicitly changed.

## Deployment Update — 2026-08-31
- Production Linux deployment now prefers `install-services.sh`: the syslog
  listener runs as root only for TCP/UDP 514, while the Waitress dashboard and
  API pollers run as the dedicated non-login system account `siem`. The
  installer creates `siem` automatically; no personal username/UID argument is
  accepted. Both services share the `minisiem` group for SQLite/WAL access.
- Service-account hardening: `install-services.sh` creates `siem` with a
  non-login shell and `/var/lib/mini-siem` home, keeps project code/venv out of
  the service-writable set, and grants shared write only where runtime SQLite,
  `db-config.json`, and backups require it. It preflights the `siem` account's
  ability to execute the selected Python and write the SQLite directory before
  enabling services.
- The installer now prefers the repository `.venv/bin/python3` (or `.venv/bin/python`)
  before falling back to PATH. This avoids `sudo` selecting `/bin/python3`
  when Flask/Waitress are installed in the project venv.
- CentOS/RHEL SELinux lesson: copying a tree from a home directory to
  `/opt/mini_siem` with preserved labels can leave `user_home_t`; systemd then
  fails at EXEC with `status=203/EXEC` / `Permission denied` before Python
  starts. The installer detects this under `/opt` on Enforcing systems and runs
  `restorecon`; do not disable SELinux to work around it.
- Shell scripts are normalized to Unix LF to avoid `bash\\r` shebang failures.
- SQLite upgrades carry the complete cleanly-closed `siem.db`; that already
  includes `api_pollers`, `app_config`, poller cursor/encrypted secret state,
  users, logs, IOC feeds, reports/tickets, and related tables. Do not migrate
  those tables separately.

## Important Decisions
- GitHub is the shared source of truth.
- Codex and Claude may both work on this repository.
- `AGENTS.md` contains permanent working instructions; this file tracks changing
  development state.
- `patch.md` is the persistent implementation and validation ledger. Every
  material AI-assisted change must update it in the same work session.
  `AI_HANDOFF.md` remains the concise current-state/design handoff, while
  `patch.md` records concrete patches, deployment notes, validation, and planned
  slices.
- Continue using temporary databases for destructive or authentication-changing
  tests. Do not point `security_dynamic_scan.py` at production data.
- Treat the static scanner as advisory: trace flagged dynamic SQL to its source
  rather than changing safe placeholder construction merely to silence it.
- Live-rule sliding-window state is intentionally memory-only and resets when
  the listener restarts. Stored logs and generated alerts remain persistent;
  historical detection across restarts is handled by database-backed
  correlation playbooks. Do not add rule-state persistence unless this design
  is explicitly changed.
- The working Sophos Central poller design is intentional: use the
  `oauth2_sophos` scheme, exchange the configured client ID/secret at
  `https://id.sophos.com/api/v2/oauth2/token` with scope `token`, pass the JWT
  as `Authorization: Bearer <token>` to
  `https://api.central.sophos.com/whoami/v1`, discover the tenant ID and
  `apiHosts.dataRegion`, then request the path-only `/siem/v1/events` with the
  JWT and automatically selected `X-Tenant-ID` header. Access tokens are
  intentionally cached in memory and refreshed before their assumed expiry;
  the event cursor is persisted in the database so polling resumes without
  starting over. The client secret is stored encrypted in the SIEM database.
  Preserve this verified integration flow unless a change is explicitly
  requested and tested against Sophos.
- `integrations/sophos_poller_bundle/` is the supported transfer package for
  embedding the same poller in another SIEM that implements the documented
  `conn_factory`, `ingest_fn`, and `resolve_secret_fn` callbacks and matching
  `api_pollers` schema. The target must provide connector-scoped event-ID
  deduplication before enabling polling; a partial batch can be replayed before
  the next cursor is persisted.

## Proposed Feature Roadmap (candidate next builds)
Substantial feature work (not bug fixes) recommended for the platform. Each
notes what it is, why it matters, and where it fits the existing modules.

1. Alert case management / triage lifecycle.
   - What: give alerts a working state machine instead of fire-and-forget.
     Status (new -> acknowledged -> investigating -> closed), assignee,
     analyst notes/comments, and a disposition (true-positive / false-positive /
     benign) recorded back onto the alert. Add suppression/mute rules
     (silence a known-noisy source+rule for a chosen window).
   - Why: this is the largest workflow gap. Detection, enrichment, and AI
     triage already exist, but there is no way for an analyst to actually work
     an alert or to control alert-fatigue noise.
   - Where: extends the `alerts` table and the dashboard alert feed; audit the
     lifecycle transitions through the existing audit trail.

2. Sigma rule ingestion.
   - What: import the open-source Sigma detection ruleset and compile matching
     rules into the live engine, instead of hand-writing `Rule` subclasses.
   - Why: highest detection-coverage leverage; one feature multiplies the
     number of detections by orders of magnitude using community content.
   - Where: `rules.py` / `correlations.py` (a Sigma -> engine compiler plus a
     management surface for enabling/disabling imported rules).

3. GeoIP enrichment + impossible-travel detection.
   - What: enrich source IPs with geo/ASN at ingest using an offline MaxMind
     database (no external calls, consistent with the local-first design),
     expose country/ASN as searchable fields, and add an impossible-travel
     detection (same user authenticating from two locations too far apart to
     travel between in the elapsed time).
   - Why: a classic high-value SIEM detection the platform cannot currently do,
     and enrichment that improves search and correlation broadly.
   - Where: ingest/enrichment path alongside existing field materialization;
     new detection in the correlation/playbook layer.

4. Visual analytics overview page.
   - What: a dashboard landing view with charts - events/min time-series,
     top talkers, alert severity trend, alerts-over-time, and silent-source
     status - instead of only tabular log search and alert feeds.
   - Why: high-visibility overview that a real SIEM opens on; the data already
     lives in SQLite, so this is primarily a query + charting layer.
   - Where: new dashboard page/route querying existing tables; no new ingest
     pipeline required.

## Failed or Deferred Approaches
- Dashboard and dynamic security checks were attempted with the system
  `python3`, but Flask was unavailable. No dependency installation was performed
  during this inspection.

## Recommended Next Step
Because the maintainer considers the platform well tested and stable, the next
work is feature development rather than a test/CI catch-up. Pick one item from
the Proposed Feature Roadmap and implement it on the working branch. Suggested
starting point: item 1 (alert case management / triage lifecycle), the largest
analyst-workflow gap; item 2 (Sigma rule ingestion) is the alternative if
deepening detection coverage is the priority. Record the concrete work in
`patch.md` per the AGENTS.md ledger rule. Before merging any dashboard-side
work, run the Flask-dependent smoke checks (`dashboard.py`/`siem.py --help`,
`security_dynamic_scan.py`) in an environment with `requirements.txt` installed.

## Last Verified
- Runtime/test baseline: 2026-08-17 in `/Users/mattlai/Projects/mini_siem` at
  commit `fa41fc5` (`Initial import of Mini SIEM project`).
- Handoff update: 2026-08-21 (documentation-only; no code changed). Status,
  roadmap, and next-step guidance refreshed and merged with `main`.
- Sophos portable bundle: 2026-08-28. Two offline mocked-flow tests passed;
  Python AST and JSON parsing passed; no external API was contacted.

### 2026-09-01 AI triage trigger/context contract — SUPERSEDED
- Warning-or-higher log severity (`warning`, `error`, `critical`, `alert`, `emergency`) is now a generic severity-alert trigger.
- Severity-triggered alerts preserve the original normalized event severity.
- Historical behavior at this superseded stage: `notice`/`informational` did not trigger AI triage on their own and context used a same-source latest-40 model. **Do not use this as the current contract**; the later corrected trigger/related and progressive-profile entries supersede it.
- Do not change the Sophos OAuth -> Whoami -> regional SIEM flow casually. Initial `/siem/v1/events` uses `from_date`; continuation uses `cursor`. Its regression test is a protected contract.
- GitHub Actions workflow is intentionally read-only (`permissions: contents: read`).

### 2026-09-01 AI source-context threshold semantics — SUPERSEDED
`high_severity_event` is a protected source-context trigger: warning-or-higher events always reach auto-triage when AI auto-triage is enabled, regardless of `ai_auto_triage_min_severity`. The configured minimum severity continues to filter ordinary alerts. `gather_alert_context()` intentionally includes same-source lower-severity notice/informational events so the LLM studies surrounding activity rather than only the trigger row.


### 2026-09-01 corrected trigger vs related-evidence contract (supersedes the two temporary AI trigger/context notes above)
- **Trigger and related evidence are separate concerns.** Do not apply evidence filters as trigger rules or vice versa.
- NXLog Windows JSON is identified narrowly by JSON format plus `EventID` and `Channel=Security|System`, matching the shipped NXLog `to_json()` configuration. NXLog `warning`, `error`, `critical`, `alert`, and `emergency` create `nxlog_severity_event`; NXLog `notice`/`informational` do not trigger on their own.
- `nxlog_severity_event` bypasses `ai_auto_triage_min_severity`, so an operator setting `error` does not suppress an NXLog `warning` trigger.
- Firewall/CEF does **not** inherit the NXLog warning/error trigger. Existing firewall/correlation triggers remain unchanged. The pre-existing non-NXLog generic severity trigger remains `critical`/`alert`/`emergency` only.
- After any eligible alert is selected for LLM triage, related evidence is cross-source and severity-agnostic. Resolve a trigger IP (alert source IP when it is an IP; IOC IP for an IP IOC hit; otherwise linked-event/indexed fields such as API/poller `endpoint_ip`) and retrieve profile-bounded related logs where that IP appears as normalized `source_ip`, normalized `destination`, transport `peer_ip`, or indexed source/destination aliases.
- Related evidence may therefore mix NXLog, FortiGate/CEF, Sophos/API/poller, and other products. An IP appearing as a firewall destination is intentionally related to an NXLog/API trigger for the same IP.
- Sophos OAuth -> Whoami -> regional API flow remains protected; initial SIEM v1 events request uses `from_date`, continuation uses `cursor`.

### 2026-09-01 progressive related-investigation profiles — HISTORICAL DESIGN, SUPERSEDED BY RUNTIME IMPLEMENTATION BELOW

- Added canonical `DEVELOPMENT.md`, `OPERATION.md`, and `PRODUCT.md` documentation for a three-stage related-evidence investigation model.
- Trigger and related evidence remain separate concepts: source-specific trigger rules decide when to investigate; related evidence remains cross-source, cross-severity, and source/destination aware.
- Planned profile progression is strictly sequential: run Short and ask the LLM first; expand to Medium only when Short reports no suspicious/relevant evidence or insufficient evidence; expand to Long only when Medium reports the same. Stop widening immediately when suspicious/relevant evidence is found.
- Initial profile defaults are investigation-specific rather than one global window. Medium is generally about 3x Short; Long is generally about 10x Short, with asymmetric windows where the investigation type requires them.
- Long evidence must be reduced/aggregated before LLM submission; repeated network events should be summarized rather than dumped raw.
- Historical note: this was documentation-only at the time; it is superseded by the runtime implementation entry immediately below.

## 2026-09-01 progressive AI investigation runtime

- Short -> Medium -> Long profile escalation is IMPLEMENTED in runtime, not documentation-only.
- New `investigation_profiles.py` defines auth anomaly, malware/Sophos, IOC hit, account/privilege, firewall C2/beaconing, and conservative generic fallback windows/budgets.
- `ai_soc.gather_alert_context(..., stage=...)` performs stage-bounded, cross-source/cross-severity related-IP retrieval across source/destination/peer/indexed endpoint fields.
- Profile timing is anchored on linked trigger-event timestamps when available (important for delayed/API ingestion), with `alert.created_at` only as fallback.
- `ai_worker.TriageWorker` calls the LLM at Short first and widens only on `NO_SUSPICIOUS` or `INSUFFICIENT`; `SUSPICIOUS` stops immediately. Missing decision markers fail open to wider scope.
- Long reduces repeated exact event shapes to representative rows and supplies count/first/last/median-interval summaries.
- Regression coverage proves Short stop, Short->Medium escalation, Short->Medium->Long escalation, missing-marker fail-open behavior, trigger-event anchoring, Long raw-evidence reduction, and preservation of NXLog/firewall trigger separation.
- Stage provenance is stored in `alerts.ai_analysis`; dedicated UI transition fields are not yet implemented.
- Auto-triage is immediate, so future portions of after-trigger windows are capped at current time.
- Verification for this slice: 30 non-Flask tests passed (`test_db`, `test_sql_helpers`, `test_investigation_profiles`, `test_warning_ai_context`, Sophos bundle); `compileall` passed; static security scan reported 0 findings; shell syntax/LF checks passed. Full Flask route/import collection remains NOT RUN in this packaging environment because Flask is not installed and outbound pip installation is unavailable. GitHub Actions is expected to run the complete requirements-backed suite.

## 2026-09-03 ingest performance hardening

Implemented in the current working tree:

- Removed the per-event normalized-field commit that defeated Storage batching.
  `Storage.insert_log(..., fields=...)` now writes the log and all extracted
  fields atomically under one storage lock and one commit-batch unit.
- Added `Connection.executemany()` and converted normalized-field inserts plus
  re-index/backfill row writes to batch execution.
- Added bounded receive/processing separation via `IngestPipeline` with
  configurable worker count/queue capacity, receive-boundary timestamps,
  explicit UDP/non-UDP drop counters, high-water metrics, worker failure counts,
  and queue draining on shutdown.
- Added a bounded asynchronous `ForwarderManager` queue and dedicated sender
  thread so network I/O is no longer on the ingest path; forwarding queue drops
  and high-water state are visible.
- Made mutable RuleEngine threshold state thread-safe for parallel workers and
  made FieldIndexer/IOC reload loops stoppable for clean shutdown.
- Existing SQLite FTS5 message indexing was retained rather than duplicated.
  Database initialization/search now probes availability, rolls back a failed
  FTS setup cleanly, and falls back to `LIKE`; PostgreSQL query construction no
  longer assumes the SQLite FTS table exists.
- Runtime defaults surfaced in `db-config.json`: commit batch 100, max delay
  100 ms, 4 ingest workers, 10,000-event ingest queue, 10,000-event forwarding
  queue.

Verification in the packaging environment:

- New targeted ingest/indexing suite: **6 passed**. It covers atomic batched
  log+field visibility, single-call field `executemany`, batched re-index,
  visible UDP queue overflow/drain behavior, non-blocking forwarding enqueue,
  and FTS5 trigger synchronization/capability probing.
- Broader non-Flask regression: **34 passed** (`test_db`, `test_sql_helpers`,
  `test_investigation_profiles`, `test_warning_ai_context`, and the new ingest
  performance suite).
- `python3 -m compileall -q .`: PASS.
- `python3 security_static_scan.py`: PASS, 21 files scanned / 0 findings.
- Final bounded local stress check accepted/persisted **5,000/5,000** events and
  **15,000** field rows with zero ingest/forward drops or processing failures at
  about **6,934 events/s** on a temporary local SQLite filesystem. This is an
  engineering smoke measurement, not a production throughput claim.
- Full `python3 -m pytest -q` collection is blocked in this environment because
  Flask is absent: `tests/test_dashboard_routes.py` fails import with
  `ModuleNotFoundError: No module named 'flask'`. Do not treat that environment
  gap as a passing full-suite result.

Next recommended step: run the complete requirements-backed suite in CI and a
representative sustained/burst soak on the actual deployment filesystem and
forwarding destinations. For PostgreSQL deployments, add a real-PostgreSQL
concurrency/transaction test; for very high forwarding volume, consider one
sender queue per destination so a slow destination does not head-of-line block
other forwarders (it already cannot block ingestion).
