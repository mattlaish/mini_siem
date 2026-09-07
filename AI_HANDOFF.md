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
  Canonical operator installation instructions are in `INSTALLATION.md`.
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

## 2026-09-03 dashboard search boolean controls + cascade timeline

Current dashboard behavior now includes scoped boolean controls for Log Search:
Source, Host, and Destination each support comma-separated terms with AND/OR;
field query-builder chips also support AND/OR using repeated `fc=field=value`
parameters, including multiple values for the same field. Operators are scoped
to their own positive term group; all filter families remain ANDed and
exclusions always apply. Message FTS/LIKE text search and field filters are
therefore simultaneously effective in one query.

The Log Search toolbar also has a Cascade Timeline button beside Export filtered.
It reuses the same current filters, retrieves up to 500 events chronologically,
and displays browser-local `Mon D YYYY HH:MM` timestamps, actual range, compact
source -> destination/host routing, first-sentence/clause message summaries, and
recognized Event IDs. The timeline is an `aria-modal` overlay above the dashboard
rather than an inline panel; close via the top-right `×`, `Esc`, or shaded
backdrop. Background scrolling is locked while open, focus is contained/restored,
and the underlying Log Search filters/table state are preserved.

Validation performed without Flask installed: Python compile passed; inline JS
`node --check` passed; an exact-function SQLite harness passed 11 boolean/search
composition cases; a separate exact-function FTS5 harness proved message text +
field filtering together with FTS enabled; timeline helper checks passed. A new
`tests/test_log_search_logic.py` covers the same backend contracts for normal
requirements-backed CI, but that pytest file was not executed in this packaging
environment because Flask/Werkzeug are absent.
The overlay follow-up passed `compileall`, dashboard inline-JS `node --check`,
static structural modal checks, and the static security scanner (0 findings / 21
files). The non-Flask regression selection has 34 passes; 2 import tests remain
blocked solely by the missing Flask dependency.


## 2026-09-03 native Cascade Timeline dialog update

Cascade Timeline is now implemented with a native HTML `<dialog>` rather than a
custom fixed-position overlay. `showModal()` provides top-layer modal behavior,
background inertness/focus handling, and native Esc cancellation. Desktop sizing
is ~90vw x 85vh (max 1600px wide), while <=700px is full-screen. The internal
timeline remains horizontally scrollable. The top-right `×` and backdrop close
paths remain. Clicking a timeline card closes the dialog and scrolls/highlights
the corresponding main-table row; if that row is not in the normal 200-row page,
the dashboard issues an exact-ID lookup combined with the same current filters,
adds the row to the table, and then locates it without changing filter state.
Validation: compileall and inline-JavaScript `node --check` pass; 37 selected
non-Flask tests pass (34 existing + 3 native-dialog structural/navigation tests);
static security scan reports 0 findings / 21 files. Full pytest remains blocked
only at the two Flask-dependent collection points because Flask is absent from
the packaging environment, so those are explicitly not counted as passes.

## 2026-09-04 live-refresh / text-search performance update

Dashboard auto-refresh is now endpoint-specific rather than one 5-second
`refreshAll`: `/api/logs` runs every 5 seconds and `/api/stats` every 15 seconds;
Alerts and AI queue are initial/manual/on-demand only. Stats/log requests use
per-endpoint `AbortController` coordination, background overlap is skipped,
user/filter actions cancel stale requests, hidden tabs pause polling, and
background calls keep `X-Background-Poll`. Cascade Timeline is on-demand only
and has an explicit Refresh button; normal log polling never reconstructs its
500-event DOM.

Database message search now has one operator control: top-level
`text_search=auto|fts|trigram|like`, with `MINISIEM_TEXT_SEARCH` as a runtime
query override. Provisioning follows the persisted config mode, not the
per-process environment override. SQLite auto uses FTS5 when queryable and otherwise LIKE. PostgreSQL setup is mode-aware: auto attempts `idx_logs_message_fts` as a native
simple-configuration tsvector GIN expression index plus optional `pg_trgm` /
`idx_logs_message_trgm`; fts only attempts the FTS index; trigram only attempts
the extension/trigram index; like skips search-index DDL. PostgreSQL auto prefers
indexed FTS, then indexed trigram, then ILIKE. Extension/index failures are non-fatal.
Search capability probes are cached on the hot path and refreshed by Stats. `/api/stats` returns
non-secret search status and the Log Search UI displays it. The common query
builder preserves TEXT AND source/host/destination AND field AND severity/time
semantics on every engine.

Testing truth boundary: the new source has selected non-Flask/unit/static
coverage, but live PostgreSQL index creation/query-plan validation is still
DEFERRED/NOT_RUN. Do not claim pg_trgm installation or GIN use on a deployment
until its dashboard status or direct PostgreSQL validation confirms it. A stats
rollup table was intentionally deferred pending measured `/api/stats` latency.


## 2026-09-04 Performance Phase 3

The current performance line additionally implements five requested optimizations:
(1) Log Search incremental DOM refresh plus event delegation; (2) per-event listener
stdout off by default with 10-second aggregate ingest metrics; (3) normalized
`log_fields.value_norm` with exact/prefix covering indexes and explicit contains
syntax; (4) indexed Source/Host/Destination exact/prefix semantics with composite
time-aware indexes and alias lookups through `value_norm`; and (5) bounded SQLite
busy/cache/temp/mmap/WAL-checkpoint/rate-limited-optimize tuning. The structured
filter syntax is: identity full-IP exact / bare-text prefix / `=value` exact /
`value*` prefix / `*value*` contains; fields use `field=value` exact,
`field=value*` prefix, `field=*value*` contains. Existing cross-family AND and
per-family AND/OR semantics remain unchanged.

SQLite migration is additive: `value_norm` is added if missing, historical field rows
are lowercased into it once, then the new covering index is created. New ingest and
reindex writes populate display and normalized values together. Real PostgreSQL
validation of the new lower()/text_pattern_ops identity indexes and field
text_pattern_ops index is still DEFERRED/NOT_RUN.
Packaging-environment verification for this phase: 56 selected non-Flask tests
passed, Python compileall and dashboard JavaScript syntax passed, and the static
security scanner reports 0 findings across 21 Python files. Flask-dependent tests
remain unrun here because Flask is absent. Local SQLite EXPLAIN confirmed the new
field exact/prefix and hostname prefix indexes are actually selected; real PostgreSQL
EXPLAIN/ANALYZE remains deferred.

## 2026-09-04 Performance Phase 4

Current performance architecture is now receive queue -> parser/extraction pool ->
bounded dedicated `DBWriter` -> bounded post-persist pool -> asynchronous forwarding.
The main log path uses `db_writer_queue_size=20000`, `db_writer_batch_size=100`, and
`db_writer_max_delay_ms=75` by default. The former `commit_batch_size` /
`commit_max_delay_ms` settings remain for lower-volume compatibility/auxiliary
Storage writes; they are no longer the main socket-ingest batching mechanism.

The DB writer commits log + `log_fields` + total/hourly/source rollups in one
transaction, then releases the durable `log_id` to RuleEngine/IOC processing.
Post-processing cannot intentionally create an alert for a failed log batch.
Dashboard telemetry is cross-process via `runtime_stats.ingest_telemetry` and includes
receive/DB/post queue data, drops/failures, ingest rate, average batch size, and rolling
commit avg/p50/p95. Rollup tables are `runtime_stats`, `hourly_log_stats`, and
`source_last_seen`; existing installs get a one-time totals/source bootstrap and only
14 days of hourly historical bootstrap. The Dashboard's 24-hour log count remains
exact by combining whole-hour rollups with at most two indexed partial-hour raw
ranges. DB-writer shutdown also flushes a partial tail immediately via its queued
sentinel instead of waiting out the configured max-delay.

`/api/logs?envelope=1` returns `rows`, `newest_cursor`, `oldest_cursor`, and
`maybe_more`. `after_cursor` is chronologically newer and `before_cursor` older using
the `(received_at,id)` tuple; the supported cursor sort is default/recent-first or
explicit `received_at`. Dashboard background Log Search uses the cursor and fetches
only new rows, while manual/filter/sort changes full-refresh. The legacy array API is
preserved when `envelope` is omitted.

Cascade Timeline remains a native `<dialog>` but is now incremental and virtualized:
initial latest-500 load, own `after_cursor` on Refresh, latest-5,000 in-memory bound,
and only viewport-near cards mounted in DOM. Clicking a timeline card still closes the
dialog and focuses/fetches the exact log under the unchanged active filters.

Live PostgreSQL Phase-4 planner validation is still **DEFERRED/NOT_RUN** in the current
packaging environment because neither a PostgreSQL instance nor psycopg2 is available.
Use `tools/postgres_phase4_validation.py` only against a disposable test/bench/dev DB;
it provisions the current schema/indexes and records real `EXPLAIN (ANALYZE, BUFFERS)`
evidence for every important query shape. Do not claim GIN/pg_trgm/query-plan success
until that harness passes on the target PostgreSQL family.

Next performance candidates after Phase 4 are IOC domain/URL matcher scaling,
retention/lifecycle maintenance (including decrement/rebuild semantics for rollups),
and PostgreSQL partitioning/horizontal ingest only after measured data volume justifies
them.
Final Phase-4 release verification: **64 non-Flask tests passed**, including **8/8** dedicated Phase-4 tests. `compileall`, Dashboard JavaScript syntax, and the static security scan passed (21 Python files, 0 findings). A 5,000-event bounded SQLite smoke persisted and post-processed every accepted event, wrote 15,000 normalized field rows, updated rollups for all 5,000 events, used 50 DB batches averaging 100 events, and recorded zero drops/failures. The observed ~15,287 events/s and commit latency figures are temporary-filesystem engineering smoke data only. Full Flask-dependent collection remains BLOCKED/NOT_RUN because Flask is unavailable and outbound package installation is unavailable. Live PostgreSQL planner validation remains DEFERRED/NOT_RUN. The final release archive must remain cache/.git-free and be re-extracted for artifact verification.


## Performance Phase 5 Update — 2026-09-04

- Phase 5 builds on the verified Phase-4 pipeline without changing existing search or
  AND/OR semantics. The main additions are opt-in bounded retention, scalable domain/URL
  IOC matching, privacy-preserving query latency telemetry, explicit overload health,
  conservative SQLite lifecycle maintenance, and bounded PostgreSQL session/pool policy.
- `maintenance.py` owns background retention/SQLite housekeeping and deliberately shares
  the listener Storage connection/lock. Retention is OFF by default. If enabled, raw
  logs, `log_fields`, and `ioc_matches` age out in bounded batches; alerts remain as
  detection records. Do not change this to an unbounded delete or online full `VACUUM`.
- `telemetry.py` is the canonical performance/health helper. Query samples are bounded
  and labelled only by coarse class; do not add raw text, filter values, IPs, usernames,
  SQL parameter values, or other sensitive/high-cardinality labels to telemetry.
- IOC matching now uses direct maps for IP/hash, extracted suffix lookup for domains, and
  `MultiPatternMatcher` (Aho-Corasick) for URL substrings. Preserve the existing semantic
  contract when optimizing further; avoid returning to event×IOC nested substring loops.
- Operational health is current-state oriented. It uses queue utilization plus recent
  interval drops/failures and latency thresholds, rather than cumulative historical drop
  counters. The Dashboard and Health page surface `HEALTHY`, `DEGRADED`, or `OVERLOADED`
  with reasons.
- PostgreSQL live plan validation is still required on a real disposable server. Run
  `tools/postgres_phase5_validation.py` with a test/dev/bench database and retain the
  JSON EXPLAIN evidence. Do not mark PostgreSQL production readiness complete from the
  existence of the harness alone.
- Canonical deployment identity is unchanged: `install-services.sh` creates the `siem`
  non-login system account and `minisiem` group; dashboard runs `siem:minisiem`, listener
  remains `root:minisiem` only because it binds privileged syslog port 514.
- See `TESTING.md` for exact final Phase-5 executable evidence and all DEFERRED/NOT_RUN
  gates. Keep README, INSTALLATION, DEVELOPMENT, AI_HANDOFF, TESTING, Help, and OPERATION
  synchronized if retention/maintenance/health behavior changes later.

## Performance Phase 6 Update — 2026-09-04

- The canonical lifecycle is now **archive-first, never age-delete**. Do not reintroduce automatic `DELETE ... WHERE received_at < ...` retention. Legacy `retention` config keys are compatibility debris only and are ignored by the new maintenance path.
- `archive.py` is the archive authority. It creates sealed SQLite segments with `archive_payloads` (exact content-addressed payload), `archive_occurrences` (one original global log ID + receive time per event), `archive_payload_fields`, compatible `logs`/`log_fields` views, and payload-level FTS5 where available. Raw evidence is zlib-compressed once per exact payload.
- Main-DB tables `archive_segments` and `archive_occurrence_catalog` are the catalog. Copy mode is idempotent because an already-cataloged log ID is not archived again. Move mode may remove only the hot `logs`/`log_fields` copy after segment commit + offline compaction + SHA-256 + manifest + catalog + reopen verification. It does not decrement `total_logs` or historical rollups and it does not delete IOC/alert evidence.
- Normal `/api/logs` search merges archive evidence when required and deduplicates hot/archive overlap by original ID. `purpose=live`/`after_cursor` remains hot-only for efficiency. Text search, Source/Host/Destination AND/OR, severity/time filters, extracted-field exact/prefix/contains filters, cursor semantics, Timeline, and row field expansion must continue to mean the same thing in both tiers.
- **Never silently skip a required archive segment.** Archive read/query failure is a 503 availability error so analysts cannot confuse an unavailable segment with zero matching logs. This truth boundary is more important than returning partial results.
- Query telemetry is non-authoritative and fail-open. `_record_query_telemetry_safe` exists specifically so telemetry failures cannot break or alter real Log Search. Do not add a telemetry cache/result shortcut into the data path.
- `maintenance.py` now performs archive orchestration plus non-destructive SQLite housekeeping only: PASSIVE checkpoint, incremental vacuum/free-page reclamation when already supported, optimize, and rate-limited quick_check. Full live VACUUM and age-delete are prohibited.
- Operational health exposes queue signals/thresholds and remains observation-only. No adaptive dropping/throttling has been authorized.
- IOC architecture is deliberately undecided after Phase 6. Preserve the existing matcher until a separate product decision chooses embedded IOC versus a distinct enrichment service.
- Service identity remains unchanged: `install-services.sh` creates non-login `siem` + `minisiem`; dashboard runs `siem:minisiem`; listener remains `root:minisiem` when binding privileged 514. Default archive permissions are root:`minisiem` 2750 directory and 0640 segment/manifest files.
- Keep README.md, INSTALLATION.md, OPERATION.md, DEVELOPMENT.md, AI_HANDOFF.md, TESTING.md and Dashboard Help synchronized with this evidence-lifecycle truth boundary.

### Phase 6 final release evidence — 2026-09-04

The Phase-6 closeout gate has executable evidence: **81 selected non-Flask tests pass**,
including **7/7 archive/evidence lifecycle tests**. Python compileall, Dashboard/Health
JavaScript syntax, shell syntax, and the static security scan pass; the scanner reports
**0 findings across 24 Python files**. A 5,000-event bounded ingest smoke persisted and
post-processed every accepted event with 15,000 field rows, 5,000 rollup events,
50 DB batches averaging 100, and zero drops/failures. A separate 20,000-occurrence
archive smoke produced one verified sealed segment with 100 exact unique payloads and
19,900 storage-deduplicated duplicate occurrences while preserving every occurrence ID
and receive time; copy mode retained all hot copies. See `TESTING.md` for exact commands,
measurements, and truth boundaries.

Full Flask-dependent collection is still **BLOCKED / NOT RUN** in the packaging
container because Flask is absent. Live PostgreSQL remains **DEFERRED / NOT RUN** because
no PostgreSQL instance/client or psycopg2 is available. Never promote either gate to
PASS without real execution evidence.
