# Development Contract

## 2026-09-03 — Ingest concurrency and indexing performance hardening

Implemented performance/runtime changes:

- Socket receive no longer executes the full ingest pipeline inline. UDP/TCP
  listeners timestamp raw input and submit it to a bounded `IngestPipeline`; a
  configurable worker pool performs parsing, persistence, detection, IOC
  matching, normalized-field handling, and forwarding enqueue. Queue saturation
  is explicit through accepted/dropped counters rather than silent user-space
  loss. UDP uses non-blocking enqueue; TCP/API use a short bounded wait.
- `Storage.insert_log(event, fields=...)` persists the log plus normalized field
  rows under one `storage.lock` acquisition and one transaction batch unit.
  Field indexing no longer commits each event independently. The default commit
  policy is 100 write units or 100 ms, with final shutdown flush.
- Normalized field writes use `executemany`; re-index/backfill groups deletes and
  inserts into batched transactions rather than committing each row/event.
- Forwarding is isolated behind its own bounded queue and sender thread. Slow
  network destinations can grow/drop that forwarding queue, but they do not run
  on the collector ingest workers.
- RuleEngine mutable threshold-window state is synchronized for the new worker
  model. Auxiliary IOC/forwarder writes use Storage commit/rollback accounting.
- SQLite FTS5 message indexing already existed in the repository. This slice
  preserves its triggers/backfill and adds capability probing plus graceful
  `LIKE` fallback when FTS5 is unavailable; PostgreSQL does not reference the
  SQLite FTS virtual table.

Operational tradeoffs/invariants (historical Phase-1 behavior; the main socket
ingest path is superseded by the Phase-4 DB writer documented below):

- A batched commit creates a bounded durability window: a process/host failure
  can lose accepted work that has not committed. `commit_batch_size=1` /
  `commit_max_delay_ms=0` now controls only compatibility/auxiliary Storage
  writes. For the main listener path, `db_writer_batch_size=1` and
  `db_writer_max_delay_ms=0` disables DB micro-batching, although the bounded
  receive/DB queues still remain in-memory rather than becoming a durable broker.
- Log + normalized-field persistence is atomic within the same database
  transaction. Since Phase 4, RuleEngine/IOC post-processing receives a log ID
  only after the corresponding DB-writer transaction has committed.
- Parallel workers may change completion ordering for burst events. Receive
  timestamps are captured at the socket/API boundary and preserved.
- Bounded queues do not make overload disappear; they make overload explicit
  and measurable. Production sizing must be validated with representative
  message rates, disk latency, forwarder latency, and PostgreSQL where used.

## Purpose

This document is the canonical engineering description of mini-SIEM investigation behavior that is planned or implemented across detection triggers, related-evidence retrieval, and LLM analysis. It intentionally separates **trigger logic** from **related evidence** so that source-specific severity rules do not accidentally redefine cross-source investigation context.

## Current implementation boundary

As of 2026-09-01, the runtime already has the corrected trigger/related split:

- NXLog Windows JSON `warning` and above can trigger `nxlog_severity_event`.
- NXLog `notice` and `informational` do not trigger by themselves.
- Firewall `warning`/`error` do not inherit the NXLog trigger rule; firewall keeps its own existing rules and the existing non-NXLog critical/alert/emergency path.
- Once an alert legitimately enters AI triage, related evidence can cross NXLog, firewall, Sophos/API, and other sources and can match an investigation IP in source, destination, endpoint, peer, or indexed extracted fields.
- Related evidence is not filtered by severity.

The **Short -> Medium -> Long investigation profile state machine is now implemented in runtime**. `investigation_profiles.py` defines the investigation classes and per-stage windows/budgets; `ai_soc.py` performs profile-bounded cross-source related retrieval and Long-stage reduction; `ai_worker.py` executes the sequential LLM escalation state machine. The final `alerts.ai_analysis` preserves every stage that actually ran, including stage window, candidate/evidence counts, decision, and model analysis.

## Core invariant: Trigger is not Related

### Trigger

A trigger answers only:

> Is this event or deterministic finding important enough to start an investigation?

Trigger policy remains source/rule specific. Examples:

- NXLog Windows warning/error-or-higher events can start an investigation.
- API/poller findings use their own existing trigger rules.
- Firewall keeps its existing independent trigger rules; NXLog severity policy must never be applied to firewall warning/error traffic merely because both sources share normalized severity names.
- Scheduled playbook findings remain a separate deterministic path; their currently documented alert/ticket gap is unaffected by this investigation-profile design.

### Related evidence

Related evidence answers:

> Once an investigation starts, what other telemetry may explain the same entity or activity?

Related evidence is intentionally cross-source and cross-severity. A trigger IP may be related when it appears as:

- `source_ip`
- destination / destination IP
- peer IP
- Sophos/API endpoint IP
- indexed or normalized `src`, `src_ip`, `dst`, `dst_ip`, `client_ip`, `target`, or equivalent source/destination fields
- later entity resolvers may add hostname, endpoint ID, user/account, process, domain, URL, hash, or IOC relationships

Firewall evidence is therefore valid related evidence for an NXLog or API-triggered investigation even though firewall warning/error does not use the NXLog trigger rule.

## Progressive Investigation Profiles

The investigation engine retrieves and analyzes evidence progressively rather than choosing one global time window for every alert.

### State machine

```text
Legitimate trigger
      |
      v
SHORT candidate retrieval
      |
      v
LLM analysis #1
      |
      +-- suspicious/relevant evidence found --> stop expansion; produce finding
      |
      +-- no suspicious evidence / evidence insufficient
                    |
                    v
             MEDIUM retrieval
                    |
                    v
             LLM analysis #2
                    |
                    +-- suspicious/relevant evidence found --> stop expansion; produce finding
                    |
                    +-- no suspicious evidence / evidence insufficient
                                  |
                                  v
                           LONG retrieval
                                  |
                                  v
                           LLM analysis #3
                                  |
                                  v
                         final finding / no finding
```

**Critical rule:** the LLM is not given Short, Medium, and Long evidence at the same time. The system begins with Short. Medium is requested only when Short does not reveal suspicious/relevant evidence or cannot support a confident conclusion. Long is requested only when Medium also fails to reveal suspicious/relevant evidence or remains insufficient.

This keeps routine investigations cheap and focused while preserving a controlled path to deeper historical correlation.

### Shared automatic/manual execution

`ai_soc.run_progressive_triage()` is the single runtime state-machine entry point. The background `TriageWorker` and the manual `/api/ai/triage` endpoint both call it, so manual and automatic investigations cannot silently diverge into different profile behavior.

Profile windows anchor on the timestamp of linked trigger telemetry when available; alert creation time is only a fallback for alerts without a usable linked-event timestamp.

## Initial profile defaults

These are initial product/engineering defaults, not universal mathematical truths. They are asymmetric where incident semantics require more history before or after the trigger. Medium is generally about 3x the Short scope; Long is generally about 10x, with trigger-specific rounding and asymmetry.

| Investigation class | Short | Medium | Long | Default starting profile |
| --- | --- | --- | --- | --- |
| NXLog 4625 failed logon / authentication anomaly | 5m before / 10m after | 15m before / 30m after | 1h before / 2h after | Short |
| Malware / Sophos detection | 2h before / 1h after | 6h before / 3h after | 24h before / 12h after | Short, then progressive escalation |
| IOC hit | 4h before / 1h after | 12h before / 3h after | 48h before / 12h after | Short, then progressive escalation |
| Account creation / privilege change | 15m before / 1h after | 45m before / 3h after | 3h before / 10h after | Short, then progressive escalation |
| Firewall C2 / beaconing investigation | 1h before / 30m after | 3h before / 90m after | 12h before / 5h after | Short, then progressive escalation |

The table defines retrieval scope, not trigger policy. For example, a firewall C2 profile can be used after a firewall-specific trigger or after another source produces a legitimate trigger whose related evidence indicates possible C2 behavior.

## Evidence budgets and reduction

Profile expansion must not mean "send every raw matching log to the LLM". When linked trigger events have usable timestamps, their latest trigger-event time anchors the profile window; `alert.created_at` is only the fallback. This prevents delayed API/poller ingestion from centering an investigation hours after the actual security event.

### Short

- Narrow temporal scope.
- Current runtime candidate budget: up to 100 matching events.
- Current runtime resolves an investigation IP from the alert/trigger event/indexed endpoint fields and matches that IP across source, destination, peer, and indexed related fields.
- Up to 80 evidence events are submitted after ranking toward trigger-time proximity.

### Medium

- Roughly 3x Short temporal scope for the investigation class.
- Current runtime candidate budget: up to 250 matching events before evidence reduction.
- Current runtime remains centered on the resolved investigation IP while retaining source/destination/peer/indexed endpoint matching across products.
- Evidence is ranked toward trigger-time proximity. Deterministic one-hop expansion to additional users/hosts/processes remains a future enhancement.

### Long

- Roughly 10x Short temporal scope for the investigation class.
- Runtime candidate budgets range from 1,000 to 1,500 events depending on investigation class.
- Repeated exact event shapes are reduced to representative first/closest/last evidence before the LLM call.
- Repeated-pattern summaries include count, first seen, last seen, median interval, source, destination, application, severity, and representative event IDs.
- Up to 120 reduced raw evidence events are submitted, plus bounded pattern summaries.

## LLM escalation contract

The LLM response for every progressive stage is required to end with one of these machine-readable dispositions:

- `INVESTIGATION_DECISION: SUSPICIOUS` -> stop widening immediately
- `INVESTIGATION_DECISION: NO_SUSPICIOUS` -> widen to the next profile when one exists
- `INVESTIGATION_DECISION: INSUFFICIENT` -> widen to the next profile when one exists

If the model omits or corrupts the marker, runtime treats the stage as `INSUFFICIENT` and widens rather than prematurely stopping.

The LLM must not directly choose arbitrary database ranges or bypass profile limits. The application controls retrieval and profile transitions; the LLM evaluates the bounded evidence provided to it.

Long is terminal for this three-profile workflow unless a future deterministic playbook or operator action explicitly starts a different investigation.

## Correlation features

Time is a feature of relatedness, not the definition of relatedness. Candidate ranking should eventually account for:

- trigger type and investigation class
- entity identity and relationship strength
- source vs destination direction
- temporal distance from the trigger
- repeated or periodic behavior
- authentication/process/network sequence semantics
- source diversity and corroboration
- deterministic IOC or playbook matches
- normalized severity as context, never as the sole relatedness criterion

## Implementation status and remaining enhancements

Implemented runtime behavior:

1. Investigation-profile definitions and deterministic trigger-class mapping.
2. Profile-bounded related retrieval replacing generic latest-N retrieval for AI triage.
3. Cross-source IP matching across source, destination, peer, Sophos/API endpoint and indexed related fields.
4. Trigger-event-time anchoring, trigger-proximity ranking, and per-stage candidate/evidence budgets.
5. Structured LLM disposition controlled by the application.
6. Immediate stop on `SUSPICIOUS`; sequential widening only on `NO_SUSPICIOUS` or `INSUFFICIENT`.
7. Long-stage repeated-pattern grouping, representative-event reduction, and periodicity summaries.
8. Regression tests covering NXLog/firewall trigger separation, cross-source related evidence, profile windows, profile classification, and Short -> Medium -> Long call sequencing.
9. Stage provenance is persisted in `alerts.ai_analysis` for every stage that actually ran.

Remaining enhancements, not prerequisites for the core progressive state machine:

- dedicated UI fields/timeline for profile transitions instead of reading stage provenance from `ai_analysis`
- deterministic one-hop expansion beyond the resolved IP into users, hosts, processes, domains, hashes, and other entities
- richer significance/source-diversity ranking beyond current trigger-proximity ranking
- configurable profile tuning in the UI after operational telemetry is collected

### Runtime timing note

The configured windows include both before-trigger and after-trigger scope. Auto-triage remains immediate; runtime therefore caps a stage's future end at the current time instead of waiting minutes or hours for the full after-window to mature. A later re-investigation/replay feature can use the full historical after-window once that telemetry exists.

## Non-goals

- Do not redefine firewall severity to match NXLog severity semantics.
- Do not make informational/notice events standalone NXLog triggers merely so they can be included as related evidence.
- Do not use one global fixed time window for every investigation type.
- Do not run all three profiles for every alert.
- Do not dump an unbounded Long-profile raw event set into the LLM.
- Do not allow the LLM to perform blocking enforcement actions; this design concerns investigation context and analysis only.


## 2026-09-03 — Service-account installation documentation

- Added `INSTALLATION.md` as the canonical Linux installation guide.
- Documented the `install-services.sh` identity contract explicitly: dedicated non-login system account `siem`, primary group `minisiem`, home `/var/lib/mini-siem`, dashboard running as `siem:minisiem`, and listener running as `root:minisiem` only for privileged port 514.
- Documented that operators do not create or substitute a personal user for `siem`; the installer creates/reconciles the service account and validates its runtime access.
- Added install verification commands (`getent`, `id`, `systemctl`, `ss`, process ownership) plus upgrade guidance that preserves `.git/` and re-runs `install-services.sh` after application-file updates.
- README now links directly to the canonical installation guide.

## 2026-09-03 — Log Search scoped boolean filters and cascade timeline

Implemented dashboard/query changes:

- Source, Host, and Destination now expose explicit AND/OR selectors for their
  comma-separated positive terms. OR is scoped to that one concept; other
  filter families stay ANDed, and `!term`/`!=term` exclusions always stay
  conjunctive.
- Direct `field=value` filters now use repeated `fc=` query parameters rather
  than overwriting `f_<field>` values in `URLSearchParams`. This preserves
  duplicate field names such as `event_id=4624 OR event_id=4625`. Existing
  `f_<field>` per-column filters remain supported, and old `fc_op=or` links
  without explicit `fc=` parameters retain their legacy positive-filter OR
  behavior.
- The query builder keeps message text search in the base WHERE and composes
  extracted-field joins/EXISTS predicates with that base WHERE using AND.
  Therefore text search and field filtering are guaranteed to apply together;
  `fc_op=or` only changes the positive field-chip subgroup.
- Added a toggleable Cascade Timeline beside Export filtered. It reuses the
  exact active Log Search parameters, overrides only sort/limit for a
  chronological presentation, renders up to 500 events on a horizontally
  scrollable time-proportional axis, and shows the actual displayed range,
  source -> destination/host route, first meaningful Message sentence/clause,
  and a recognized Event ID badge. Time labels use `Jul 25 2011 23:15` style in
  browser-local time.
- Added Help/README documentation for operator scoping and timeline behavior.
- Follow-up UI patch: Cascade Timeline now opens as an `aria-modal` overlay above
  the dashboard instead of expanding inline. It has a top-right `×`, supports
  `Esc` and shaded-backdrop dismissal, locks background scrolling while open,
  traps keyboard focus inside the dialog, restores focus on close, and preserves
  the underlying Log Search filters/table state. Clicking a timeline card that
  has a visible matching table row closes the overlay and scrolls to that row.

Verification completed in the packaging environment:

- `dashboard.py` and the new search-logic regression test compile successfully.
- Dashboard inline JavaScript passes `node --check`.
- Exact-function SQLite harness: 11 scoped boolean/filter-composition checks
  passed, including duplicate-field OR, Source/Host/Destination OR, exclusion
  behavior, and message-text + field-filter conjunction.
- Exact-function SQLite FTS5 harness: text + field composition passed with FTS5
  enabled as well as with the LIKE fallback harness.
- Timeline helper checks passed for `Jul 25 2011 23:15` formatting, first-sentence
  summary extraction, Event ID recognition, and route formatting.
- Full Flask route pytest remains not runnable in this packaging environment
  because Flask/Werkzeug are not installed; the added
  `tests/test_log_search_logic.py` is intended for the normal requirements-backed
  CI/runtime test environment and is not counted as passed here.
- Overlay follow-up validation: `python -m compileall -q .` and dashboard inline
  JavaScript `node --check` passed; structural assertions confirmed the modal,
  close control, Escape/backdrop dismissal, body-scroll lock, focus restoration,
  and removal of the old inline `timelinePanel`. The static security scan reports
  0 findings across 21 files. The non-Flask regression selection reports 34
  passed; its 2 import tests that transitively require `dashboard.py` fail only
  because Flask is absent and are not counted as passes.


## 2026-09-03 — Native dialog Cascade Timeline follow-up

- Replaced the hand-built fixed overlay/focus trap with the browser-native HTML
  `<dialog>` API (`showModal()` / `close()`). Native modal semantics now provide
  top-layer rendering, background inertness, focus containment, and Escape
  handling without duplicating those mechanisms in dashboard JavaScript.
- Desktop sizing is approximately 90vw x 85vh (capped at 1600px wide). At
  <=700px the dialog becomes full-screen using 100vw x 100dvh with a 100vh
  fallback. The timeline content keeps its own horizontal scroller.
- Preserved the explicit top-right `×` and shaded-backdrop close behaviors.
- Timeline-card navigation now always attempts to return to the selected log in
  the main table. If the selected timeline event is outside the normal 200-row
  table page, `loadLogs({focusId})` performs an additional exact-ID request using
  the same active filters, appends that matching row without altering the filter
  state, scrolls it into view, and briefly highlights it.
- Removed manual body-scroll locking and custom Tab focus trapping because native
  modal dialog semantics own those responsibilities.
- Verification for this follow-up: `python -m compileall -q .` passed; dashboard
  inline JavaScript passed `node --check`; 37 selected non-Flask tests passed
  (the previous 34 plus 3 native-dialog structural/navigation tests); static
  security scan reported 0 findings across 21 files. Full pytest remains blocked
  at collection for `test_dashboard_routes.py` and `test_log_search_logic.py`
  because Flask is not installed in this packaging environment; those tests are
  not counted as passed.

## 2026-09-04 — Dashboard live-refresh and database-native text-search performance

- Split dashboard auto-refresh into Log Search every 5 seconds and Stats every
  15 seconds. Alerts and AI queue are no longer background-polled; initial/manual
  refresh remains their explicit on-demand path.
- Added per-endpoint request coordination with `AbortController`: a background
  poll is skipped while the same endpoint is in flight, while a user/filter
  request cancels the stale request. Hidden browser tabs pause live polling and
  refresh live data when visible again. Background requests retain the
  `X-Background-Poll` header so they do not extend idle sessions.
- Cascade Timeline no longer rebuilds when Log Search auto-refreshes. It loads on
  dialog open and now has its own manual Refresh control.
- Added `text_search=auto|fts|trigram|like` plus
  `MINISIEM_TEXT_SEARCH` runtime query override; index provisioning intentionally
  follows the persisted config mode so per-service environment overrides do not
  create inconsistent schema behavior. SQLite auto retains FTS5/LIKE behavior.
  PostgreSQL setup is mode-aware: auto attempts native FTS plus optional
  `pg_trgm`, fts creates only its GIN expression index, trigram creates only its
  extension/index path, and like skips search-index DDL. Search auto prefers
  indexed PostgreSQL FTS, then indexed trigram, then ILIKE fallback. Search
  capability probes are cached for 60 seconds on the hot log-query path; the
  15-second Stats poll refreshes capability status for operator visibility.
- `/api/stats` exposes non-secret effective text-search status; Log Search shows
  the selected engine and whether it is indexed. Message search remains
  conjunctive with all structured and extracted-field filters.
- Validation in the packaging environment: 48 selected non-Flask regression
  tests passed, including new live-refresh/native-search tests. JavaScript syntax,
  Python compile checks, and static scan are run as release gates. Live
  PostgreSQL FTS/pg_trgm index creation/query planning remains DEFERRED/NOT_RUN
  until a real PostgreSQL instance is available. Full Flask-dependent collection
  remains environment-blocked when Flask is absent and is not counted as passed.
- Deliberately not implemented in this slice: a stats rollup/counter table. The
  lower-frequency `/api/stats` polling is applied first; rollups should be added
  only when measured stats latency justifies the additional ingest/write state.


## 2026-09-04 — Performance Phase 3: incremental dashboard + indexed structured filters

- Log Search background refresh now has an incremental recent-first DOM path. If the
  active query shape is unchanged and only newer IDs arrived, existing rows remain
  mounted, new row pairs are prepended, and rows outside the 200-row window are
  removed. Identical result IDs cause no table mutation. Non-default sorts, query
  shape changes, focus-ID navigation, and large gaps safely fall back to a full render.
- Replaced per-row/per-expanded-field listener attachment with one delegated click and
  dragstart handler on `#logsBody`. Background polling also stops rebuilding the log
  header / extracted-filter controls every five seconds.
- Per-event ingest stdout/journald logging is disabled by default. Optional debug
  behavior is `ingest_event_logging=true`; normal operation emits aggregate
  processed/received/dropped/failed/queue/rate output at the configurable
  `ingest_stats_interval_seconds` (10s default).
- Added `log_fields.value_norm` and one-time historical backfill. New/reindexed field
  rows store the original display value plus lowercase normalized value.
  `(field, value_norm, log_id)` is a covering exact/prefix index (NOCASE on SQLite,
  `text_pattern_ops` on PostgreSQL). `field=value` is exact, `field=value*` prefix,
  and `field=*value*` is the explicit contains slow path.
- Source/Host/Destination matching now favors indexed exact/prefix predicates. Full IP
  is exact; bare text is prefix; `=value` exact; `value*` prefix; `*value*` explicit
  contains. Existing subnet syntax remains. Added case-insensitive composite indexes
  `(identity, received_at, id)` using SQLite NOCASE or PostgreSQL lower()+
  `text_pattern_ops`; configured aliases use `log_fields.value_norm`. Cross-filter AND
  and per-box AND/OR semantics are unchanged.
- SQLite connections now apply bounded tuning: driver + PRAGMA busy timeout, bounded
  cache size, optional MEMORY temp store, bounded mmap, WAL autocheckpoint, and
  once-per-database/per-process rate-limited `PRAGMA optimize`.
- New `tests/test_performance_phase3.py` covers legacy value_norm migration/backfill,
  actual SQLite EXPLAIN plans for identity and field prefix indexes, match syntax,
  SQLite PRAGMAs, per-event stdout default-off, and incremental/event-delegated DOM
  structure. Live PostgreSQL text_pattern_ops planning remains DEFERRED/NOT_RUN until
  a PostgreSQL test instance is available.
- Verification in the packaging environment: 56 selected non-Flask tests passed;
  `compileall` passed; dashboard inline JavaScript passed `node --check`; static
  security scan reported 0 findings across 21 Python files. Full Flask-dependent
  collection/import remains environment-blocked because Flask is not installed and
  is not counted as passed. A bounded local temporary-SQLite query check over 50,000
  logs showed EXPLAIN selecting `idx_lf_field_value_norm` for exact fields and
  `idx_logs_host_time_ci` for hostname prefix; warmed median timings were ~1.01 ms
  for a 25,000-row field-count lookup, ~0.09 ms for hostname prefix, and ~3.72 ms
  for the deliberately unindexed contains scan. These are engineering smoke numbers,
  not production benchmarks. A 5,000-event local ingest smoke persisted all 5,000
  logs / 20,000 fields with zero drops/failures at ~5,807 events/s; also not a
  production throughput claim.

## 2026-09-04 — Performance Phase 4: scale and incremental data path

- Replaced the high-volume per-worker log-write path with a three-stage bounded
  pipeline: receive queue -> parser/extraction workers -> one dedicated DB writer
  -> post-persist rule/IOC/forwarder workers. `DBWriter` owns a bounded prepared
  queue and commits micro-batches using `db_writer_batch_size` (100 default) or
  `db_writer_max_delay_ms` (75 ms default), whichever boundary arrives first.
  SQLite's single-writer nature is now explicit instead of several ingest workers
  repeatedly contending on the same connection lock.
- Persistence ordering is intentional: a batch transaction creates the log and
  normalized fields, updates rollups, commits, and only then emits `(log_id,event)`
  to post-persist processing. Rule and IOC alerts therefore never intentionally
  reference a log whose persistence transaction failed. A full post-persist queue
  backpressures the DB writer; a full DB-writer queue is bounded and counted as a
  visible failure/drop instead of growing memory without limit.
- Added DB-writer telemetry: queue depth/capacity/high-water, rows written/failed,
  batch count/average size, and a rolling 256-commit latency window with
  average/p50/p95. Aggregate ingest telemetry is periodically persisted to
  `runtime_stats` so the separate Dashboard process can display it.
- Added `runtime_stats`, `hourly_log_stats`, and `source_last_seen`. Log totals,
  hourly severity counts, and source first/last-seen/count update transactionally
  with log insertion. Alert totals update transactionally with `Storage.insert_alert`.
  Existing databases bootstrap total counters and source state once; hourly
  historical bootstrap is deliberately bounded to the most recent 14 days.
  `/api/stats` uses these rollups for total events and silent-source detection;
  exact 24-hour log counts combine whole-hour rollups with at most two indexed
  partial-hour raw ranges. Alert/IOC 24-hour queries remain indexed raw queries.
- DB-writer shutdown queues its sentinel behind all accepted prepared events before
  waiting. That causes a low-traffic partial batch to commit immediately during
  graceful shutdown instead of sleeping through the configured max-delay window.
- Added `(received_at,id)` keyset support and `idx_logs_received_id`. `/api/logs`
  supports `envelope=1`, opaque `newest_cursor`/`oldest_cursor`, `after_cursor`,
  `before_cursor`, plus ID-only compatibility cursors. Cursor semantics are
  chronological (`after` newer / `before` older) and are limited to default or
  `received_at` ordering; equal timestamps are stably ordered by ID. No OFFSET is
  used for the cursor path.
- Dashboard live Log Search now requests only unseen rows with `after_cursor` on
  the normal recent-first path. New rows are prepended to the existing DOM and
  the 200-row visible window is trimmed; filter/sort/manual changes still perform
  a full query. A burst equal to the page limit leaves the cursor at the newest
  fetched item so later background requests continue catching up rather than
  skipping the unseen middle.
- Cascade Timeline now initially loads the latest 500 matching events, saves its
  own cursor, and its Refresh button requests only newer matches. Timeline layout
  metadata is kept in memory, while card/stem/dot DOM is virtualized to the
  visible horizontal viewport plus a 700px buffer. The logical canvas can grow
  without permanently mounting thousands of cards; client memory is capped at
  the latest 5,000 loaded timeline events. Native `<dialog>`, X/Esc/backdrop close,
  filter summary, date format, and event -> main-log focus behavior are preserved.
- Added `tools/postgres_phase4_validation.py`. It is a guarded test-DB harness
  that initializes PostgreSQL schema/indexes, loads a bounded synthetic dataset,
  ANALYZEs it, and emits `EXPLAIN (ANALYZE, BUFFERS)` for FTS, pg_trgm substring,
  field exact/prefix, Source/Host/Destination prefix/exact, combined time filters,
  text+field conjunction, and cursor pagination. The packaging environment has
  no PostgreSQL client/psycopg2/server, so live PostgreSQL validation remains
  **DEFERRED / NOT RUN** and must not be represented as passed.
- Added `tests/test_performance_phase4.py` for DB micro-batching/rollups,
  low-traffic shutdown tail flush, exact partial-hour 24h rollup composition,
  post-persist ordering, alert counters, equal-timestamp cursor stability,
  Phase-4 schema/index presence, and Dashboard cursor/virtualization structure.
  Exact final release verification is recorded in `TESTING.md`.
### Final Phase-4 verification / packaging

- Final non-Flask regression: **64 passed**; dedicated Phase-4 suite: **8 passed**. Full Flask-dependent collection was attempted but cannot run in this offline packaging environment because Flask/Waitress are not installed and the Python package index is unreachable; this remains BLOCKED/NOT_RUN rather than passed.
- `compileall` passed; Dashboard `static/csrf.js` and the `index.html` inline JavaScript passed `node --check`; the repository static security scanner examined 21 Python files and reported 0 findings.
- Final bounded SQLite smoke accepted/persisted/processed **5,000/5,000/5,000** events with **15,000** normalized field rows, **5,000** rollup events, **50** DB micro-batches (100.0 average), and zero ingest drops, DB-queue drops, DB failures, or processing failures. The temporary-filesystem run measured about **15,287 events/s**, commit average **5.754 ms**, p50 **4.848 ms**, p95 **5.732 ms**; these are engineering regression numbers, not production sizing claims.
- Release packaging is clean: `.git`, `.pytest_cache`, `__pycache__`, `.pyc`, and other transient caches are excluded, and the archive is re-extracted before final verification. Live PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` remains DEFERRED/NOT_RUN.


## 2026-09-04 — Performance Phase 5: retention, IOC scale, telemetry, and operational hardening

- Added an opt-in retention/lifecycle worker (`maintenance.py`). Automatic deletion is
  deliberately disabled by default so an upgrade cannot silently delete evidence.
  When enabled, cleanup uses bounded ID batches and removes expired `log_fields`,
  `ioc_matches`, and raw `logs` in one listener-owned DB transaction/lock domain.
  Alerts are retained as detection/audit records even when referenced raw logs age out.
  `runtime_stats.total_logs`, historical hourly rollups, the cutoff partial-hour rollup,
  and stale `source_last_seen` rows are reconciled after the raw backlog is caught up.
- SQLite maintenance is intentionally conservative: monitor WAL/page/freelist state,
  issue a PASSIVE checkpoint only after the configured WAL threshold, run bounded
  `incremental_vacuum(N)` only on databases already using `auto_vacuum=INCREMENTAL`,
  and rate-limit normal `PRAGMA optimize`. No online full `VACUUM` was introduced.
  Fresh SQLite databases request incremental auto-vacuum at creation; existing DBs are
  not rewritten or full-vacuumed merely to change that setting.
- Reworked IOC scale characteristics. IP/hash remain direct lookups. Domain matching
  extracts domain-shaped tokens once and checks exact/parent suffixes against the IOC
  map. URL matching now uses a dependency-free Aho-Corasick `MultiPatternMatcher`
  rebuilt on IOC reload, avoiding one substring search per configured URL IOC for every
  event while preserving URL-substring semantics.
- Added process-local, bounded query telemetry (`telemetry.py`) keyed only by an
  allowlisted coarse query class such as `logs.live`, `logs.timeline`, `logs.text`,
  `logs.field`, or `stats`. It records durations/counts/p50/p95/max/slow counts but
  intentionally never stores query text, field values, IP filters, usernames, or other
  search content. Slow-query stdout is class/duration-only and rate-limited.
- Added `HEALTHY` / `DEGRADED` / `OVERLOADED` operational-state derivation from current
  queue pressure, recent interval drops/failures, DB commit p95, query p95, and telemetry
  freshness. Historical cumulative drop counters do not permanently poison state; the
  health calculation uses recent interval deltas. Forwarder queue telemetry is included
  in the listener's persisted ingest telemetry.
- Dashboard Log Search status now exposes operational health, a privacy-preserving query
  latency summary, and retention state. `/api/stats` returns query telemetry, maintenance
  status, and SQLite file/page/freelist metadata without replacing the Phase-4 rollup
  path with full-table counts. The Health page presents the same operational view.
- PostgreSQL production bounds now include connection-pool min/max, connect timeout,
  statement timeout, lock timeout, idle-in-transaction timeout, and application name.
  Each pooled checkout reapplies those bounded session settings. The existing guarded
  query-plan harness was extended for Phase 5 and is available through
  `tools/postgres_phase5_validation.py`; live PostgreSQL validation remains a separate
  required gate when an actual disposable PostgreSQL instance is available.
- `configure-db.py`, `db-config.json`, `README.md`, `INSTALLATION.md`, Help, operations,
  testing, and handoff documentation were updated so retention remains explicit/opt-in
  and the new thresholds are operator-visible rather than hidden defaults.
- Added `tests/test_performance_phase5.py` covering bounded retention cleanup/disabled
  default, fresh SQLite incremental-auto-vacuum behavior, no-full-VACUUM maintenance,
  URL automaton matching, domain suffix matching, query telemetry privacy/percentiles,
  interval-based overload state, nested config defaults, Dashboard structure, and the
  PostgreSQL Phase-5 validation profile. Packaging-environment verification and deferred
  live gates are recorded in `TESTING.md`; live PostgreSQL EXPLAIN and sustained
  production network/storage soak must not be inferred from local SQLite tests.

## 2026-09-04 — Performance Phase 6: archive-first evidence lifecycle and operational truth

- Replaced the Phase-5 age-delete retention model with an archive-first evidence lifecycle. `db.DEFAULT_CONFIG` no longer contains an active `retention` policy. A stale legacy `retention` key may remain in an upgraded operator config, but `maintenance.py` deliberately ignores it and never age-deletes logs.
- Added `archive.py`. Eligible hot events can be copied into immutable SQLite archive segments. Each segment is compacted offline, SHA-256 checksummed, given a JSON manifest, cataloged in `archive_segments`, and re-open verified before it becomes authoritative. `archive_occurrence_catalog` records each original global log ID exactly once so copy mode is idempotent.
- Archive deduplication is exact/content-addressed, not fuzzy. `archive_payloads` stores a byte-equivalent event payload once, `archive_occurrences` preserves every original log ID and receive time, and `archive_payload_fields` stores the corresponding extracted field set once per payload. `raw` is zlib-compressed in the archive payload. Similar events are never collapsed merely because their Event ID/message pattern is alike.
- Archive segments expose compatible `logs` and `log_fields` views plus payload-level FTS5 when available. Dashboard Log Search now merges hot and sealed archive results using the same text/Source/Host/Destination/severity/time/field filter semantics. Copy-mode overlap is deduplicated by original global log ID. Live `after_cursor` polling stays hot-only because archives contain older evidence.
- `mode=move` means hot-copy eviction, not evidence deletion. The new segment is committed, compacted, hashed, manifested, cataloged and verified first; only then are the corresponding hot `logs`/`log_fields` removed. `ioc_matches`, alerts, `runtime_stats.total_logs`, hourly rollups and `source_last_seen` remain intact because evidence still exists. Changing an existing archive from copy to move verifies already-sealed segments before evicting their hot duplicates.
- Archive availability is fail-closed for historical search correctness. If a cataloged segment required by a query cannot be opened/read, `/api/logs` returns an explicit 503 archive-availability error rather than a false empty/partial history. `/api/log-fields/<id>` also falls back to the archive catalog after a hot copy has moved.
- Query telemetry was made explicitly fail-open through `_record_query_telemetry_safe()`. Telemetry failure cannot modify query predicates, cursors, field filters, archive inclusion, or response rows. The Stats path also tolerates telemetry snapshot failure.
- SQLite maintenance remains non-destructive and separate from evidence lifecycle: bounded PASSIVE WAL checkpoint, bounded incremental free-page reclamation only for `auto_vacuum=INCREMENTAL`, `PRAGMA optimize`, page/freelist visibility, and a rate-limited `PRAGMA quick_check`. No live automatic full `VACUUM` or unbounded age-delete exists.
- Expanded overload health output with per-queue pressure signals and the thresholds used for `HEALTHY` / `DEGRADED` / `OVERLOADED`. This is observability only and does not autonomously throttle/drop traffic.
- IOC architecture is intentionally frozen for this phase. The existing Phase-5 matcher implementation remains available, but no decision was made to further couple IOC matching to mini-SIEM or split it into an external enrichment service.
- Added `tools/archive_verify.py` for checksum/readability verification and `tools/archive_now.py` for a bounded operator-triggered archive/maintenance cycle. The standard installer creates the default `archive/` directory as root:`minisiem` mode `2750`; sealed segments/manifests are mode `0640` so the `siem` dashboard service can read them through the shared group without world-readable evidence.

### Final Phase-6 verification / packaging

- Selected non-Flask regression: **81 passed**, including **7/7** dedicated
  `test_evidence_archive_phase6.py` checks.
- Full pytest was attempted and remains **BLOCKED / NOT RUN** only because Flask is
  unavailable in the packaging environment; the two collection blockers are
  `tests/test_dashboard_routes.py` and `tests/test_log_search_logic.py`.
- `compileall`, Dashboard/Health/static JavaScript syntax, three shell syntax checks,
  and the static security scan all passed; the scanner covered **24 Python files with
  0 findings**.
- Final source-tree ingest smoke accepted/persisted/processed **5,000/5,000/5,000**
  events, wrote **15,000** field rows and **5,000** rollup events in **50** DB batches
  averaging 100, with zero ingest/DB-queue drops and zero processing/DB failures.
- Final archive/dedup smoke sealed **20,000 occurrences** representing **100 exact
  unique payloads** into one verified segment: **19,900 duplicate occurrences** were
  storage-deduplicated without losing any original occurrence ID/time. Copy mode kept
  all 20,000 hot rows. Checksum/readability verification passed.
- Live PostgreSQL remains **DEFERRED / NOT RUN** because no PostgreSQL server/client or
  `psycopg2` exists in the packaging environment. Do not interpret harness presence as
  planner validation.
- Release packaging must remain free of `.git`, pytest/cache artifacts, `__pycache__`,
  `.pyc/.pyo`, temporary archive segments, and test databases; the release ZIP is
  re-extracted and subjected to the release gate before delivery.
