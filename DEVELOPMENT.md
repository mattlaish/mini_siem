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

Operational tradeoffs/invariants:

- A batched commit creates a bounded durability window: a process/host failure
  can lose the current uncommitted batch. Operators needing per-event commit can
  set `commit_batch_size=1` and `commit_max_delay_ms=0`.
- Log + normalized-field persistence is atomic within the same database
  transaction. Rules/IOC processing occurs only after the insert has produced a
  log ID, but the commit may still be deferred by the batching policy.
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
