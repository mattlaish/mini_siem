# AI Handover Prompt - mini-SIEM

## Contains guard, DEFAULT-partition alert, Top values — 2026-11-09 (cloud session)

The three small items agreed after the 1M events/day estimate:

- Contains guard (dashboard.py `_contains_recent_page`): PostgreSQL
  newest-first pages with `*text*` field filters check the newest 50,000
  events of the window first (strpos probes, no trigram join) and stop at the
  page size. Exact by construction: returned only when a full page is found
  or the window is smaller than the guard; otherwise the indexed query runs.
  Skipped for OR mode, explicit sorts, and pages beyond the guard.
- DEFAULT-partition alert (workers.py `StorageHealthWatcher`,
  `check_default_partitions`): PostgreSQL only, lease `storage-health`,
  every 10 min; one warning alert per episode (state in app_config key
  `storage_default_partition_alert`, cleared when the partitions are empty).
- Top values (templates/index.html): toolbar button and a per-field link in
  expanded events open `/api/logs/facets?field=` with the current time range;
  click filters, "not" excludes. SQLite now answers `?field=` too.
- Fixed in passing: a second chip for the same field was shown but ignored
  (one condition per field on the server); it now replaces the first, with a
  notice.

Validation: new tests (contains guard 5, storage alert + SQLite facets 4);
full suite same 38 pre-existing failures, nothing new; static scan 8 HIGH
(unchanged); tiny PostgreSQL 16 check (30 events): guarded, fallback and
unguarded paths return identical pages; DEFAULT alert raised once, cleared
when rows moved back; browser check of the panel (counts, filter, exclude,
expanded-row link, no JS errors). No scale benchmarks run (owner's request).

Still open from the estimate: asset/identity upsert churn and multi-event
deadlock risk (event_storage_v2.py `_observe_asset`/`_observe_identity`),
OR+exclusion cost, all-history prefix/contains guards.

## Production search measurement tool — 2026-11-08 (cloud session)

Added tools/postgres_search_measure.py (step 0 of POSTGRES_SEARCH.md):
read-only at the server via PGOPTIONS (verified: INSERT is refused),
statement/lock limits, searches through the dashboard's own query code with
values sampled from the last 24 h, pasted Log Search page URLs converted to
API filters. Tested on PostgreSQL 16 against a new-layout benchmark database
and an upgraded legacy-layout database. Waiting for the owner to run it on
production. Also fixed: a CIDR with host bits (10.1.2.3/24) made PostgreSQL
log search fail with HTTP 500 (cidr rejects host bits); it now searches the
network. Synthetic findings to confirm on production: starts-with across all
history scans every partition (4.1 s first run); OR with exclusion read 21k
blocks for 0 rows.

## PostgreSQL search slice measured — 2026-11-06 (cloud session)

Benchmarked fb51c96 with tools/postgres_search_benchmark.py on a local
PostgreSQL 16 (3,000 rows in the searched day + 60,000 over 120 days, 8
repeats), against the previous release (fd92537) with the same harness.

With history added, the previous release degraded on field searches (exact
19 ms/10,016 blocks, prefix 22 ms/13,342, OR/exclude 39 ms/21,167, CIDR
72 ms/11,363). The new layout stays flat as history grows: exact 8 ms/824,
three exact 4 ms/99, prefix 7 ms/445, OR/exclude 9 ms/1,840, CIDR 3.5 ms/58.
Serial batch ingest roughly doubled (≈310 → ≈510–600 rows/s here).
Day partitions gave no gain over month for 24 h searches at this scale and
were slower before history existed (pruning skipped on fresh partitions).

Fixed here:
- Upgrading an existing PostgreSQL database failed in owner initialization
  ("cannot change name of view column asset_hostname to search_fields"):
  security_event_context selects e.*, so it is now dropped and recreated.
  Verified: a database created by fd92537 upgrades, passes the runtime check
  and returns its old rows for all search types (fallback paths).
- Host/source/destination text filters correlated the alias lookup on each
  event's time, forcing one log_fields probe per event in the window
  (10,113 blocks vs 591 before). Now constant window bounds: 659 blocks.
- Static scan back to 8 (five fixed-fragment concatenations moved out of
  execute()); stale "41 migrations" test updated to 42.

Still open: existing installs keep an unsplit log_fields (no data migration),
so they do not get the time-split field table; "contains" with a common
substring reads every match in the window (9,959 vs 1,176 blocks before);
the DEFAULT-partition warning is a System Health notice, not an alert;
/api/logs/facets?field= has no UI; day layout not recommended for
indefinite retention (partition count).

## PostgreSQL search and storage implementation — 2026-11-06

Owner asked to implement first without testing. No test suite, PostgreSQL server,
database initialization or benchmark was run for this slice. Static syntax and
source checks only. Use the explicit Projects mini_siem root, no Git operations.

- Fresh PG field storage is time-partitioned alongside typed events; month default,
  optional fresh-install week/day, shared UTC boundaries. Legacy tables are not
  repartitioned. The maintenance function extends both trees, with no retention
  changes. System Health exposes dated DEFAULT-partition overflow.
- PG field writes are batched with event time in the raw/projection transaction;
  new projections contain normalized JSONB field arrays and omit the unnecessary
  backfill existence probe. Raw JSON, evidence and IDs stay intact.
- Typed INET/CIDR and port filters, combined exact JSONB containment, bounded
  EAV fallback/OR/negative/prefix/contains paths, field top values and limited
  DNS/URL trigrams. Search defaults to recent 24h and pins the window across
  pagination; explicit history, IDs, legacy direct API scope and SQLite remain.
- Owner migration marker 42 and updated split-role grants are required before
  PostgreSQL runtime. `pg_trgm` must be available. No production operation done.
- `POSTGRES_SEARCH.md` documents setup and limits. The optional benchmark creates
  a uniquely named database only on a marked local test server; it was not run.
  No claim of faster search or of a winning partition grain until measured.

## Workload sharing and capacity scan — 2026-11-05 (cloud session)

Requested: wire the queued ingest pipeline, add job claiming for background
workers, allow multiple ingest processes, and detect how many processes a
machine can run. See OPERATION.md "Sizing log processing and sharing
background work".

- Queued ingest (listener.py): `IngestPipeline` now has one bounded queue per
  worker thread, routed by sender (per-sender order kept); UDP drops and
  counts when full, TCP waits up to 2 s. The listener's receive threads only
  stamp arrival time and queue. SIGTERM drains up to 10 s.
- Multi-process ingest (ingest_workers.py `ProcessIngest`): spawn-started
  children each with their own Storage/RuleEngine/IOC/fields/forwarders; the
  receiver parses and routes by `rules.extract_ip(message) or source_ip`, the
  same key ThresholdRule counts by, so repeated-activity alerts are identical
  to one process (tested: 12 hits from 4 senders about one attacker = 2
  alerts). Dead children restart on a fresh queue (a killed reader can leave
  the old queue's lock held); shutdown kills children that do not exit.
- Job leases (leases.py, new `worker_leases` table): ticket, AI triage, feed
  refresh, report scheduler (one lease each) and every cloud connection
  (`poller:<id>`, shared across processes). Missing table = previous
  single-process behaviour with a warning.
- Capacity scan (capacity.py, tools/capacity_advisor.py, System Health card,
  Settings form, `GET /api/capacity`, `POST /api/capacity/benchmark`,
  `POST /api/ingest-settings`, all admin-only and audited): CPU affinity and
  cgroup v1/v2 quota, memory and container limit, load, database location,
  kernel UDP buffer ceiling and RcvbufErrors, enabled indicator count;
  optional measured process memory and CPU-only benchmark. SQLite -> one
  process. `"processes": "auto"` sizes at listener start.
- Found and fixed while testing: (1) a fresh database (SQLite or PostgreSQL)
  was baselined as fully migrated although its base `forwarders` table lacked
  `origin_mode`/`tcp_framing`, so the listener crashed at start on any new
  database; base schema fixed and `initialize()` now re-adds any recorded
  ADD COLUMN that is missing. (2) The listener never enlarged its UDP socket
  buffer; a 300-message burst lost 44 datagrams in the kernel. It now
  requests 4 MB (`udp_buffer_kb`), and 300/300 arrive in both modes.

Validation: tests/test_workers_and_capacity.py 25 PASS; full suite 523 PASS /
same 38 pre-existing failures; static scan 8 HIGH; real listener processes in
both modes (UDP burst, SIGTERM) store 300/300 with correct alerts; browser
checks of the Health card and Settings form for admin/analyst/viewer PASS
with no JS errors or permission denials. Not done: PostgreSQL multi-process
load test, multi-host lease failover on real hosts, siem.py all-in-one stays
unqueued.

## Review of the 2026-11-01 upload (ddbf4a0) — cloud session, 2026-11-01

Checked the recovery/connector upload against the October 21 work: every
October 21 feature (guided setup, role-aware Settings, pickers, recovery helpers,
bulk triage, near-miss replay, background polls) is still present. The new
database-verified sessions, default-deny write guard (analyst list matches real
endpoint names), outbound transport and connector bearer boundary were reviewed;
no regressions found in them. Fixed:

- `pytest` from the repository root collected `return/mini-siem/source/tests`,
  whose module names collide with `tests/`: 52 collection errors. Added
  `pytest.ini` (norecursedirs includes `return`).
- That exposed `integrations/sophos_poller_bundle/test_bundle.py` importing the
  application's `api_poller` instead of its own snapshot copy (passed before by
  coincidence). It now imports the snapshot copy when collected as a package and
  still works standalone inside the bundle directory.
- Draft connection test (`POST /api/pollers/test`) answered a failed provider step
  with HTTP 502, which `MS.getJSON` shows as a generic server error, hiding the
  failed step. It now returns 200 with ok=false like the saved test, and uses the
  same one-hour window (was the 24-hour first-run lookback).
- The new 15-second cloud-connection refresh did not use `MS.background`, so an
  open Settings page kept idle sessions alive; it now runs in the background and
  only while that section is open.
- `/api/logs` paging built its MAX(id) query by concatenation (safe, fixed
  names) and raised the static scan to 9 HIGH; now two fixed statements (8).

Validation: full suite 498 PASS / same 38 pre-existing failures; static scan 8
HIGH; truth gate PASS; browser pass as admin/analyst/viewer over all 11 pages:
no JS errors, no failed requests, no permission_denied entries; failed draft test
shows the failed step. Not changed: outbound concurrency cap (4, fail-fast),
connector token management (CLI only), historical `return/` package.

## Latest: connector and exact historical return recovered — 2026-10-28

Active source is only `C:/Users/mattlai/Projects/mini_siem`; always set that absolute
workdir. No Git operations are authorized, regardless of AGENTS.md. Read
`RECOVERY_2026-10-28.md`, `SECURITY_HARDENING.md` and `return/README.md` first.

The owner supplied the previously missing return ZIP from
`C:/Users/mattlai/Projects/dashboard/return/dashboard/mini-siem-return-package.zip`.
Its SHA-256 is exactly the recorded b54d5041...ae25c34, bytes 1063223, 504 entries;
all 503 listed hashes match. The missing connector, token CLI, schemas, tests and
seven return tools are now recovered as actual source; bytecode reconstruction is
no longer needed. The October 27 "missing connector/archive" item is resolved.

Selective merge restored blueprint hooks, five owner-created tables/runtime
requirements, narrow bearer-only browser/CSRF exemptions, PostgreSQL least-privilege
export-state grants and protected-table ownership checks, jsonschema dev dependency
and mirrored-source truth checks. Browser sessions/roles/SSO, outbound policy,
escaping, workflow recovery, guided setup, pickers and bulk triage remain current;
no whole-file rollback of auth/dashboard/UI/poller code. Sophos, X-Forwarded-For
trust and memory-only live windows are unchanged.

Historical ZIP and exact extracted payload restored under `return/`, unchanged.
Their source/identity/logs describe October 22, NOT the current application. Do not
deploy that old source mirror, reuse its identity as current, or run preparation
over it as if it were a safe no-op. A new consolidated delivery needs fresh identity,
fixtures, acceptance evidence and ZIP. No new package was generated in this recovery.

Current Windows baseline 446 PASS / 47 FAIL / 3 SKIP; merged 479 PASS / identical
47 failures / 3 SKIP; focused 123 PASS / 0 FAIL / 0 SKIP. Syntax: 165 maintained
Python files, five static and seven inline JS, 11 rendered pages PASS; secret
patterns/truth gate PASS. Fresh historical offline replay passes 21 pages / 26 records /
6 negatives; catalog 14 PASS, 11 transport NOT_RUN, no FAIL/BLOCKED; positive old
revision sequence PASS. Real PostgreSQL/TLS/IdP/Sophos/NXLog/systemd/load/crash and
production registration remain NOT_RUN. Full R3/G1 remains PARTIAL; keep the
historical open-gaps explicit. No source changed in Dashboard and no Git executed.

Before deployment: preserve configs, database backup, owner initialization of five
connector tables and updated PostgreSQL split-role grants, then matching full-source
deployment/restart. The recovery did not touch production DBs or issue real tokens.
Backups/reports: `C:/Users/mattlai/Documents/ChatGPT/dev project/work/mini-siem-connector-recovery-20261028`.
Next: operational-gap qualification or an explicitly requested newly versioned
consolidated delivery. Historical entries below are superseded where inconsistent.

## Latest: overwrite recovery merge — 2026-10-27

Work only in `C:/Users/mattlai/Projects/mini_siem`, with explicit absolute workdir.
The owner prohibits ALL Git operations and handles synchronization manually;
this overrides the permissive Git section in AGENTS.md. Do not use the Documents
launch cwd, Desktop copies, a transfer package or a return mirror as active source.
Use scoped approval for Projects writes rather than silently relocating work.

Read `RECOVERY_2026-10-27.md` and `SECURITY_HARDENING.md` first. The October 25–26
security/workflow changes had been overwritten; no exact full source backup was
available. This is a reconstructed, tested merge, not a byte-identical restoration.
The pre-recovery source backup and test evidence are outside source at
`C:/Users/mattlai/Documents/ChatGPT/dev project/work/mini-siem-recovery-20261027`.

Recovered: database-verified sessions and roles, SSO viewer defaults/collision
rejection, default-deny mutation permissions, shared DNS-pinned bounded outbound
transport, contextual HTML escaping and provider-error-body withholding; AI-off
draft tests/write recovery, unsaved cloud tests, honest connection status, draft
guards, older log/alert history and retained-data refresh recovery.
Preserved October 21 guided setup, saved test phase/sample results, pickers,
role-aware responsive Settings, shared helpers, bulk triage and near-miss replay.
Analysts retain configured-feed fetch and display-column changes; other provider/
extraction settings stay admin-only. User-required X-Forwarded-For trust,
memory-only live rule state and Sophos OAuth/Whoami/cursor protocol are unchanged.

Deploy complete matching source/static/templates with `outbound.py`; restart both
processes. Existing cookies require login again; internal outbound services may
need exact origin allowlisting. No schema migration or production credential
replacement. The portable Sophos snapshot/ZIP has NOT been transport-hardened.

Validation on the actual Projects root: baseline 363 PASS / 47 FAIL / 3 SKIP;
recovered 446 PASS / identical 47 failing identities / 3 SKIP. Focused 247 PASS,
four known Windows permission cases deselected only from that focused run (all
remain in the full result). Six Node UI runtime tests PASS; no full browser/live
provider/PostgreSQL/NXLog/IdP/systemd qualification claimed. Windows excludes the
Linux-only systemd collection file (`pwd`). No Git or production database writes.

Important outstanding recovery: `dashboard_connector.py`, reader-token tool,
connector schemas/tests and the complete Dashboard return package are missing.
Only compiled cache remnants survive; do not execute/deploy them as recovered
source. The old return archive is absent, so its historical hash cannot be
verified. Owner reports no backup. Next task is contract/evidence-based connector
reconstruction and fresh replay/catalog/transport/identity qualification; do not
claim the entire October 26 package is restored or reuse the old archive identity.
Historical sections below describe earlier states and are superseded where they
conflict with this entry (including the old provider-error-text and test claims).

## Operator language pass - 2026-10-18

Work directly in C:/Users/mattlai/Projects/mini_siem, using scoped approval when
this chat's Documents-based sandbox lacks write access. Do not silently move source
development. No Git operations were authorized or run for this pass.

See UX_REVIEW.md for the whole-tree wording audit, implementation and remaining UX
priorities. Reviewed all 13 templates and updated 12 plus shared UI scripts without changing
routes, database schema, provider options or raw evidence. Known identifiers/status
codes get display-only labels; unknown custom labels are preserved. Named weekday
and source checkboxes round-trip the same values. Exceptions select supported rules
and named windows. Sample tests show a readable summary plus optional original JSON.
Unsaved reloads are confirmed; generated references are hidden. AI connection setup
now works before enabling AI; analysis/chat stay disabled while AI is off.

The October 17 hardening and earlier October 18 usability work are retained. This
pass did not change pollers, normalization, rule evaluation, RBAC or ingest behavior.
Direct Projects baseline on this Windows host: 306 PASS / 47 FAIL / 3 SKIP; final:
323 PASS / identical 47 FAIL / 3 SKIP, 17 new product-language tests PASS. Three
static wording assertions updated without relaxing their security assertions.
Python 145 / static JS 5 / inline JS 7 syntax, 11 rendered routes and truth gate
PASS. Browser checks used only synthetic localhost state; no captured JS errors.
This does not reproduce the historical Linux/other-environment 38-failure result,
qualify PostgreSQL/NXLog/systemd, or resolve existing non-UX test debt.

Next UX priorities: guided provider connection/test workflow, role-aware advanced
settings, visual field/time-zone choices, compact mobile Settings navigation and
consistent request recovery. Technical values required to connect products and
support diagnostics must remain exact. Local manifest refreshed for current safe
source; original October 15 ZIP untouched, no new release/package claimed.

Continue from this context.

## Critical Architecture Rules

Do NOT mix these:

1. mini-SIEM application
2. mini-SIEM Migration Tool
3. local Debug/Diagnostic Tool

The application must remain clean.

---

## Current State

Application baseline:
`mini_siem_postgresql_upgrade_baseline_hardened.zip`

Recent ingest update:
`mini_siem_cef_parser_source_update.zip`

Completed:
- PostgreSQL schema_migrations upgrade path
- existing DB baseline protection
- fresh install migration behavior
- raw event fallback
- CEF parser addition

---

## Important Previous Mistake To Avoid

Do not convert migration scripts into application features.

`/tools` migration scripts are candidates for a separate migration tool.

---

## Next Recommended Work

1. Verify CEF parser end-to-end:
   listener -> parser -> database -> API -> UI

2. Assess local diagnostic capability:
   - runtime status
   - application logs
   - sanitized config export
   - health bundle

3. Start separate mini-SIEM Migration Tool project only after application baseline is stable.

---

## Delivery Rules

- Source baseline only for implementation deliveries.
- Documentation sync must reflect actual code changes.
- Do not claim completion without source evidence and tests.


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Current State

Phase 12.3 Backup / Restore Readiness completed as IMPLEMENTED_TESTING_DEFERRED.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED

## Placeholder truth baseline — 2026-09-18

The repository has undergone full placeholder truth alignment. Treat `PLACEHOLDER_TRUTH_ALIGNMENT.md` and `PLACEHOLDER_TRUTH_INVENTORY.json` as canonical alongside ROADMAP/DEVELOPMENT/TESTING. Six runtime/qualification placeholder modules, six no-op tests, and 28 migration/release scaffolds were removed from executable source and remain `PLANNED`. Do not recreate them as `.py` until real observed-state implementation and non-trivial tests exist. Run `python tools/check_placeholder_truth.py` as a source gate.

## DB index design + case-normalization fixes — 2026-10-01

Re-applied directly on `main` after an earlier full-tree upload (`d459c41 "patched"`)
reverted the merged PR #3. Both backends fixed; both designs kept.

- `dashboard.py` `_field_value_predicate`: case-fold the needle
  (`needle = str(needle).casefold()`) before comparing against the stored
  case-folded `value_norm`. Fixes a PostgreSQL alias-field search bug where a
  mixed-case host (e.g. `DC01`) returned zero rows.
- `db.py`: configurable SQLite PRAGMA tuning in `_connect_sqlite`; a
  `COLLATE NOCASE` `value_norm` index so NOCASE comparisons are index-usable;
  `_ensure_performance_indexes(conn)` (poller partial indexes, composite
  host/time CI index) called from `initialize()`; removed the never-used
  `idx_logs_severity` / `idx_lf_field_value` CREATEs.
- `event_storage_v2.py`: dropped the two dead PostgreSQL indexes
  (`idx_se_fields_gin` — no GIN query ever filters `fields`; and
  `idx_se_event_time_brin` — duplicates the `(event_time, id)` PK).
- `tests/test_event_storage_v2.py`: schema-contract test asserts the two dead
  indexes are absent.
- `tests/test_postgres_integration.py` + `.github/workflows/test.yml`
  `pytest-postgres` job: live-PostgreSQL CI (postgres:16 service) covering
  idempotent `initialize()`, the index design, and the case-fix regression.

Validation: `compileall` clean; SQLite suite 243 passed / 38 pre-existing
unrelated failures (no regressions; the restore fixed the 2 contract tests);
truth gate PASS; all 3 live-PostgreSQL integration tests pass against real PG 16.

## Web UI redesign — 2026-10-07

Reworked all 10 Flask templates onto one shell and fixed two UI bugs.

- New `templates/base.html` + `static/app.css` + `static/app.js`: left-sidebar
  nav (mobile drawer) + slim top bar, replacing the per-page horizontal nav.
  Active item derived from `request.path` (no `dashboard.py` change).
- Single palette/component system (was 10 duplicated `:root` blocks); light/dark
  theme (prefers-color-scheme + persisted manual toggle); responsive breakpoint;
  KPI grid uses `auto-fit`. a11y: skip link, `aria-current`, `aria-live` on the
  live tables, `aria-label` on placeholder-only search inputs.
- Bug fixes in `index.html`: removed the orphaned "Refresh timeline" button
  (its only handler lived in the ignored inline body of `<script src=csrf.js>`
  and called a non-existent `loadTimeline()`); logs loading row colspan 7 → 8.
- `login.html`/`change_password.html` share the palette/dark mode but stay
  standalone (no sidebar); header/inputs made theme-safe.
- No external/CDN deps; element IDs and page scripts unchanged (behavior
  preserved). pytest unchanged at 243 passed / 38 pre-existing failures.

Follow-ups not done: externalize per-page inline `<script>` blocks to allow a
strict `script-src` CSP; move a few sub-element hardcoded light hex in secondary
pages to vars for perfect dark-mode tint.

## Managed detection + process execution monitoring — 2026-10-15

Status: IMPLEMENTED_TESTING_DEFERRED. This section supersedes the older statement
that rule-management UI is only a revisit item. See P14 in ROADMAP.md and
DETECTION_RULE_MANAGEMENT.md for the complete operating/deployment contract.

Implemented:
- Reused existing parser, source profiles, FieldIndexer, log_fields and Event
  Storage v2. Added provider/channel/ID-qualified 4688, Sysmon 1 and 4104 semantic
  mapping, process/parent/identity/time/script fields and raw-JSON reindex support.
- `/detection-rules`, `/execution-windows`, `/security-alerts`: built-in toggle/
  threshold tuning, data-only AND condition editor, no-side-effect process/script
  simulator, host/group calendars, overnight/holiday/one-off/exception-only windows,
  exact path/account and expiring ticketed exceptions, atomic full before/after
  audit and optimistic config revisions. Admin writes; authenticated read/simulate.
- Always-Critical web-parent shell and High (`error`) out-of-hours shell rules.
  java/httpd parents require a configured host role. Web-shell cannot be exempted.
- Bounded persistent duplicate evidence linking in existing alerts/app_config;
  same rule+config, host/PID/path/parent-PID/command and <=2s event time required.
  512 keys/5-minute receipt horizon, 500 evidence IDs/alert; raw events preserved.
- Per-host/source receipt monitoring every 15s, persisted silence latch and one
  warning per outage; stale monitor observations are unknown. Explicitly opt-in.
- AI usage UI works even with AI off. Provider/model input/cached/output token
  rates produce explicit USD estimates; unknown rates remain unpriced.
- Removed unused POST /api/correlate and POST /api/normalize. Active normalization,
  investigate and playbook paths remain. Machine API ingest now reaches its key
  verifier without browser login and preserves Windows JSON. Standalone HTTP and
  async listener ingest invoke RuleEngine after storage. Auth guard setup is
  idempotent. Existing threshold state remains in-memory by design.

Validation on Python 3.12/Windows with synthetic data:
- New tests: 29 PASS; focused detection/NXLog/routes/storage/lifecycle/CEF: 75 PASS
  before the final equivalent full-suite run.
- Same-environment baseline: 225 PASS / 47 FAIL / 3 SKIP.
- Updated: 254 PASS / same 47 FAIL / 3 SKIP; zero new failing test identities.
- Linux-only systemd_host_qualification collection excluded (`pwd` unavailable).
  Existing failures include absent performance/search implementations and POSIX
  permission/Unix execution assumptions; this slice does not claim a green suite.
- Placeholder truth PASS; Python/JS syntax checked. Browser with disposable
  synthetic data verified rule edit/save, simulation, windows, alert evidence and
  AI usage display. No browser errors observed. Computer-use verification led to
  clear saved/draft feedback and cancellation of newly created unsaved objects.

Deployment: update the complete source/templates/static set, install requirements
(tzdata added), restart listener and dashboard. No DB schema migration or new
runtime privileges. No Git operations were performed; synchronization is manual.

Remaining: actual Windows audit-policy/NXLog/network/notification E2E, PostgreSQL
independent-session dedup test (added opt-in CI coverage), deployed privilege/
systemd/load checks and site-approved calendar/exception/health configuration.
4104 fragment reassembly and a general process graph are optional future scope.
Existing source security/reliability backlog remains separate. Recommended next:
real Security 4688 -> NXLog -> SIEM -> configured ticket delivery qualification.

## Detection hardening — 2026-10-17

Four issues found reviewing the detection slice, all fixed on `main`:

1. Robustness. A stored detection config that failed validation (e.g. after an
   upgrade adds a built-in) made `RuleEngine.process` raise for every event, which
   in listener/siem/dashboard ingest also skipped IOC matching and forwarding, and
   broke the Detection Rules page. Now: `detection.migrate_config` upgrades older
   configs on load; the engine keeps its last good config on reload failure;
   `RuleEngine.process` never raises (errors counted in `engine.errors` /
   `engine.last_error`, logged, rolled back); one failed alert write no longer stops
   the event's other findings; `load_config_or_fallback` gives the UI defaults with
   the stored revision plus `load_warning` so an admin can save over it; the
   telemetry monitor skips its tick instead of pruning state; corrupt state rows are
   replaced. New exception restrictions apply on save only (`validate_config(strict=True)`)
   so tightened validation cannot make a stored config unloadable.
2. Hostnames. Profiles matched only the exact name, but domain-joined Windows reports
   the FQDN, so a short-name profile silently lost its schedule, roles, timezone and
   exceptions. `windows_events.host_matches/find_host_profile`: exact first, then
   short name vs FQDN; different FQDNs and IPs never cross-match; ambiguous short
   names resolve to none. Used by evaluation, schedules, exceptions and telemetry.
   Unprofiled Windows hosts are recorded (`detection_unprofiled_hosts_v1`) and listed
   at `GET /api/detection/unprofiled-hosts` / on /execution-windows with Add profile.
3. Web-shell rule is behaviour-based: defaults add tomcat8-11.exe and php-cgi.exe
   parents and, by default (`child_match: any`), alert on ANY child of a web server
   except legitimate ones (`excluded_children`: conhost, csc, cvtres, vbc, WerFault,
   wermgr, php-cgi, rotatelogs) and workers re-launching the parent's own binary
   (same full path). The earlier incident tool (whoami) is not special-cased; a tool
   list misses renamed/dropped/other binaries. `listed` mode keeps an explicit list;
   configs saved before child modes load as `listed` with their own list.
4. Custom rules gain `scope` (`windows` default = old behaviour, or `all`). All-events
   rules use generic fields plus extracted `field.<name>`; ingest call sites pass the
   extracted fields to the engine. Non-Windows matches aggregate into one alert per
   rule/host/source stream. Exceptions on rules they cannot apply to are rejected on
   save. Simulator accepts `{"event": {...}}` (any JSON) or `{"raw": "<syslog line>"}`
   through the live parse/extract path.

Validation: tests/test_detection_hardening.py 34 PASS (26 of them fail against the
pre-fix code); existing detection tests 29 PASS; full suite 306 PASS / same 38
pre-existing failures; live PostgreSQL integration 5 PASS plus a PostgreSQL
end-to-end detection run (stream aggregation, Tomcat9 -> whoami on an FQDN host);
truth gate PASS; static scan clean for detection files; browser check of scope
selector, raw-syslog simulation and unprofiled-host Add profile with no JS errors.

## Web UI usability pass — 2026-10-18

Found by walking the app with seeded data in a browser; all verified there.

- Smart refresh (dashboard): the 5s poll no longer redraws under the analyst. The
  log table holds while a row is expanded, the search is being edited, text is
  selected, the list is scrolled or a dialog is open; new rows are counted in a
  "N new events ↑" pill. The alerts panel holds while a group is expanded or a
  control is focused ("N new alerts ↑"). Stats keep updating. Polls never overlap
  and pause while the tab is hidden.
- One alert queue: /security-alerts (sidebar "Alerts") now lists every alert with
  filters (status default Open, severity, rule, assignee incl. me/unassigned, text),
  a detail drawer (status limited to valid transitions, assignee, note, history,
  key evidence fields, original events), j/k/Enter/a/Esc keys, filters in the URL,
  and a read-only drawer for viewers. `/api/alerts` gained optional filters
  (no params = unchanged) and `/api/alerts/rules`. The dashboard status menu only
  offers valid transitions.
- Live ingestion status on every page (`GET /api/ingest-status`: receiving /
  quiet / listener_down / no_data from last stored event + listener heartbeat),
  replacing the static "syslog listener" text; plus a first-run checklist on the
  dashboard while no event has ever been received.
- Readable events: `/api/logs` adds a display-only `summary` for Windows
  process/script events (e.g. "w3wp.exe → update.exe · <cmdline> · as <user>");
  stored messages are unchanged. Expanded rows show key fields first and tuck
  source keys that duplicate normalized values into a collapsed section.
- No native prompt()/alert(): MS.form dialog and MS.toast (static/app.js);
  confirm() kept for destructive actions. A test guards against regressions.
- Log-search filters live in the URL (bookmark/share/reload). One time format
  everywhere (local 24h, UTC on hover, relative in queues). Sidebar grouped into
  Investigate / Detection / Admin. Links follow the theme (were default blue in
  dark mode). "/" focuses search.

Validation: tests/test_ux_improvements.py 8 PASS; full suite 324 PASS / same 38
pre-existing failures (test_dashboard_live_refresh asserts literal strings of an
earlier unimplemented design — never polling alerts, a timeline button — and is
unchanged); truth gate PASS; static scan unchanged (8 pre-existing); 28 browser
checks (refresh hold + pills, dialogs/toasts, URL round-trip, queue keyboard and
drawer, viewer read-only, first-run, grouped nav, live status) PASS with no JS
errors or native dialogs.

## Triage at scale + near-miss replay — 2026-10-19

Follow-up review of the user's upload (4d2de4a): nothing from the earlier passes
was overridden. Fixed three small flaws it left, then added four UX features.

- Fixes: one alert-severity label everywhere (`MS.alertSeverity`; stored "error"
  shows as "High" on the dashboard and in the queue, too); unsaved detection drafts
  warn on navigation (`beforeunload`); the Threat Intel page title matches the
  sidebar ("Threat Intelligence"); `MS.isTyping` ignores checkboxes/buttons so
  the queue keys keep working after a click.
- Bulk triage: `POST /api/alerts/workflow/bulk` (analyst/admin, CSRF, 1–500 ids,
  status and/or assignee and/or note, one transaction). Each alert follows its
  own workflow rules: invalid moves are reported in `skipped` with a reason and
  are never forced; returns `updated`/`unchanged`/`skipped`; one
  `alert_workflow_bulk` audit entry plus per-alert workflow events. The single-alert
  endpoint shares the same helpers (`_workflow_request`, `_apply_alert_workflow`);
  its 409/404 behaviour is unchanged.
- Dashboard groups: a collapsed group (same rule + source) shows a member status
  summary ("2 new · 1 resolved") and "Mark all …" / "Assign all" act on every
  member through the bulk endpoint (before, only the newest member changed).
- Alerts queue: checkbox column, select-all, `x` key, and a bulk bar
  (Acknowledge / Investigating / Resolve… / Close… / Assign…). Selection is pruned
  to alerts still shown. Viewers get no checkboxes.
- Background tab: while a signed-in tab is hidden, a 60s background check
  (`/api/alerts?after_id=…`, new optional filter; sends X-Background-Poll) puts
  "(N)" new high/critical alerts in the tab title, and raises a desktop
  notification only if the user switched on "🔔 Notify" (opt-in,
  localStorage `mini-siem-notify`, browser permission). Title resets on return.
- "Why didn't a rule fire?": `GET /api/detection/near-misses?minutes=5..1440`
  (any signed-in user, read-only) replays the newest ≤20000 stored events through
  the three threshold rules with the saved threshold/window (disabled rules too)
  and reports fires plus the closest sources ("closest was 4 of 5"). The replay
  and the live `RuleEngine` share `rules.THRESHOLD_RULE_SPECS` and
  `detection.BUILTINS`; a test proves they agree. The replay uses received_at; the
  live counters are in-memory and reset on restart, so the two can differ across
  a restart.

Validation: tests/test_triage_and_near_miss.py 13 PASS; full suite 354 PASS /
same 38 pre-existing failures; static scan unchanged (8 pre-existing HIGH); 16
browser checks (group resolve-all, queue bulk with skips, select-all, keyboard after
a checkbox click, bar hides after an action, near-miss panel, draft guard, viewer
read-only, notify toggle, hidden-tab title + one notification, title restore) PASS
with no JS errors; earlier UX browser checks still PASS. The browser run found
and fixed one bug: `.aq-bulk{display:flex}` overrode `[hidden]`.

## UX_REVIEW next improvements 1–5 + permission gaps — 2026-10-21

Implemented the five "Next experience improvements" listed in UX_REVIEW.md, and
closed the permission gaps found while making Settings role-aware.

- Guided cloud setup (Settings → Cloud log connections): provider presets
  (Sophos Central / other OAuth2 / other API key) fill only blank fields; "Save
  and test connection" creates the connector (off by default) and runs
  `POST /api/pollers/<id>/test` (admin, CSRF, audited `poller_tested`). The test
  is a dry run through `api_poller.test_connection`: sign-in → Sophos account
  discovery → one events read over the last hour; it never advances the cursor
  or stores events, reports each step with the provider's own error text, and
  returns one sample event (≤4000 chars) to the admin only. "Turn on collection"
  follows a passing test. The table now says Off / Waiting for the first check /
  Connected · no events yet / Receiving / Not receiving instead of "Collecting
  logs" for never-checked connectors. `POST /api/pollers` now also returns `id`.
- Role-aware settings: Settings nav grouped (My account, Log collection, Search &
  fields, Integrations, Administration); new "Your account" section (role
  explanation + change password) is the landing section for non-admins.
  Admin-only sections show a read-only explanation and hide their controls, and
  their loaders are skipped for non-admins (no more 403s, and no audited
  `permission_denied` flood from System Health/AI usage left open by viewers).
  Threat Intelligence, dashboard pattern/column controls, AI queue buttons,
  report schedule and Health backup/diagnostics buttons follow the role. Global
  template flags `user_role`/`is_admin`/`can_triage` and `body[data-role]`.
- Permission gaps fixed (were callable by any signed-in user): admin —
  norm-patterns POST, norm-reindex, forwarders/<id>/test, tickets/test,
  ioc-feeds POST/PUT, reports/schedule, ai/test, ai/queue/retry, ai/queue/clear;
  analyst — norm-columns POST, iocs POST/import/PUT, ioc-feeds/<id>/fetch,
  reports/run, ai/triage. Blueprints use `_svc.require_analyst()` (new).
- Pickers: rule-condition field list with a description per field plus
  extracted field names seen in recent logs (`GET /api/detection/fields`), and an
  inline warning that blocks unsupported fields before Apply; time-zone list from
  the browser (`Intl.supportedValuesOf`) with typo warning, new hosts/windows
  default to the browser's zone (was hard-coded Asia/Taipei); host roles and the
  web-server rule's required role are choices (custom roles still allowed).
- Small screens: Settings uses a compact section picker (≤760px), forms stack to
  one column (≤560px), focus moves to the opened section heading and the page
  scrolls only if the heading is hidden by the top bar.
- Uniform recovery: `MS.getJSON` (operator message + technical detail),
  `MS.loading`, `MS.failed` (message · Retry/Sign in · Technical detail) used by
  Settings, Threat Intelligence, Investigations, Activity History, System Health
  and the dashboard. Failed timed refreshes keep the data shown and label it
  ("Refresh failed at … — showing data from …") instead of updating "Last
  updated". `MS.background(fn)` marks timed refreshes with X-Background-Poll;
  Health, Activity History, Threat Intelligence and Settings forwarding polls
  previously kept idle sessions alive.
- Also fixed: the ticket template hint rendered its {{placeholders}} empty (Jinja).

Validation: tests/test_guided_setup_and_roles.py 27 PASS (fake local provider for
the connection test); full suite 381 PASS / same 38 pre-existing failures (diffed
against the pre-change baseline in the same environment; one literal-source
assertion in test_syslog_troubleshoot updated to the generated nav); static scan
unchanged (8 HIGH); placeholder truth gate PASS; 26 browser checks (preset, test
pass/fail, turn on, load failure + retry, stale dashboard/health, background
header, field/time-zone/role pickers, 390px settings, viewer/analyst views with
zero permission_denied entries, no JS errors) PASS.

Not done / next: the connection test needs the connector saved first (the secret
is never sent back to the browser, so testing an unsaved form would need a
separate endpoint); no live Sophos tenant was used. The audit log
(/api/audit) remains readable by every signed-in role, as before.
