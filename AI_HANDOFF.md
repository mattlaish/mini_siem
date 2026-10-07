# AI Handover Prompt - mini-SIEM

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
