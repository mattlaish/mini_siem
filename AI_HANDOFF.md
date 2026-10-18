# AI Handover Prompt - mini-SIEM

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
