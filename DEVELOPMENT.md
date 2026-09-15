# Development Contract

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


## Installer repair hardening — 2026-09-09

A real NAS recovery exposed deployment drift: a historical dashboard unit was
present while the listener unit was missing, Flask existed only in a personal
user site-packages path, and a later deployment used `/opt/mini_siem/venv`
rather than `.venv`. The original 2026-09-01 installer remains the baseline;
it was hardened rather than replaced.

Changes:
- preserve the dedicated `siem` / `minisiem` security model;
- accept both `.venv` and `venv` project runtimes;
- bootstrap `.venv` and install `requirements.txt` when no project venv exists;
- never use system Python as the final systemd runtime;
- repair missing dependencies inside the selected project venv;
- detect stale `user_home_t` on the project or selected Python and use
  `restorecon` under SELinux Enforcing;
- explicitly detect partial listener/dashboard unit state;
- post-install verification fails closed on disabled/inactive units, wrong
  ExecStart runtime, or missing ports.

Release packaging rule: executable artifacts must be extracted from the final
ZIP and revalidated (`shebang`, `bash -n`, size/hash comparison) before delivery.


## PostgreSQL migration hardening
- Added schema_migrations tracking so startup migrations are applied once instead of replaying ALTER TABLE operations on every restart.


## PostgreSQL upgrade baseline hardening
- Existing databases without migration history are baselined before replaying migrations.
- Fresh databases continue normal migration flow.


## Bootstrap admin policy hardening
- Bootstrap admin creation is explicit only. Existing databases never receive automatic admin creation or replacement.
- User records are preserved during backend migration.


## PostgreSQL Runtime Production Implementation

Implemented PostgreSQL runtime connection resilience in the database layer with bounded pool initialization retry and connection timeout support.


## PostgreSQL Schema Migration Safety Implementation

Implemented source-level schema safety helpers:
- PostgreSQL table existence inspection
- PostgreSQL column existence inspection
- bootstrap identity preservation boundary

This prevents migration/runtime paths from assuming a clean database.


## PostgreSQL Idempotent Migration Implementation

Implemented source-level migration safety helpers:
- transaction-wrapped schema application
- required table validation before runtime use
- rollback on migration failure

This extends the PostgreSQL schema safety implementation.


## PostgreSQL Admin Bootstrap Preservation Implementation

Implemented source-level admin identity preservation boundary:
- detect existing admin identity
- avoid overwriting migrated accounts
- prevent unsafe bootstrap recreation


## PostgreSQL Migration State Validation Implementation

Implemented source-level PostgreSQL runtime state inspection:
- inspect existing database tables
- validate required application state
- avoid treating migrated databases as empty installations

## PostgreSQL Migration Investigation and Engineering Lessons (2026-09-10)

This section records the PostgreSQL migration work discussed during engineering review.

### Findings

- PostgreSQL container availability and application database migration logic are separate concerns.
- A PostgreSQL container running successfully does not guarantee that the application can start correctly.
- Duplicate database creation (`mini_siem` and `minisiem`) was identified as an operational naming mistake, not a PostgreSQL limitation.
- Existing SQLite application state, especially administrator identity, is not automatically present after moving to PostgreSQL.
- Schema initialization must not assume a clean database.

### Migration Safety Requirements

Future PostgreSQL implementation work must preserve:

- existing application identities
- existing schema state
- migration repeatability
- transaction safety
- rollback capability

### Source Baseline Rule

Implementation deliveries must remain source baselines.

The following are not considered implementation baselines:

- validation-only packages
- phase-only documents
- documentation-only synchronization packages
- accumulated migration artifact bundles

A source baseline must contain the actual application source tree and related tests/deployment material.


## CEF Parser Support

Added CEF ingest parsing with raw-message fallback.

Implemented:
- CEF header extraction
- common extension field mapping
- raw preservation on parser failure

CEF events remain visible even when vendor-specific fields cannot be normalized.

## PostgreSQL Privilege Boundary Hardening (2026-09-12)

Status: **IMPLEMENTED / LIVE POSTGRES VALIDATION DEFERRED**.

Implemented on the application mainline:

- PostgreSQL runtime processes no longer call the schema migration/DDL path. `db.ensure_runtime_ready()` validates required tables and the migration ledger and fails closed when owner migration is required.
- `db.load_config()` supports a separate component credential overlay containing only `postgres.user` and `postgres.password`; credential overlays cannot redirect host/port/database.
- listener and dashboard accept `--db-credentials` and can run under separate PostgreSQL login identities.
- secure PostgreSQL mode rejects combined `siem.py` listener+dashboard execution because one process would collapse the trust boundary.
- `tools/postgres_privilege_boundary.py` provisions `minisiem_runtime`, `minisiem_ingest`, `minisiem_dashboard`, and `minisiem_maintenance`, removes owner credentials from the base config, writes per-component credential files, and verifies effective privileges.
- runtime roles are read+append only on `logs`; `UPDATE`, `DELETE`, and `TRUNCATE` are denied. The maintenance role alone receives `DELETE` for verified hot-copy eviction.
- PostgreSQL guard triggers provide defense in depth against accidental future grants: runtime UPDATE/TRUNCATE are rejected, and DELETE is accepted only from a maintenance-role member.
- `schema_migrations` is runtime read-only. Schema change remains an explicit owner/migration operation.
- `install-services.sh` detects secure PostgreSQL mode, passes split credentials to the two services, makes dashboard credentials readable by the dashboard account only, and keeps listener/maintenance credentials root-only.
- archive execution selects/requires the maintenance credential in secure PostgreSQL mode; archive verification can use the dashboard read credential.

Security boundary intent:

```text
PostgreSQL owner/migrator   schema/DDL only, not application runtime
minisiem_ingest             SELECT + append logs; no UPDATE/DELETE/TRUNCATE logs
minisiem_dashboard          SELECT + append logs; no UPDATE/DELETE/TRUNCATE logs
minisiem_maintenance        runtime rights + DELETE logs for archive hot-copy eviction
```

Known residual boundary: the listener systemd service still runs as host root to bind port 514. Host-root compromise is therefore outside the database-credential containment guarantee and can read root-only local secret files. Dropping listener root privileges via a dedicated user/capability is a separate host-hardening slice.

## Setup Troubleshoot: constrained syslog packet capture (2026-09-13)

Status: **IMPLEMENTED / HOST-INTEGRATION VALIDATION REQUIRED**.

Added a simple **Setup -> Troubleshoot** workflow to answer whether syslog packets from one source IP are reaching the SIEM host.

Implementation invariants:

- admin-only dashboard API: `POST /api/troubleshoot/syslog-capture`;
- accepts only one validated IPv4/IPv6 source address;
- capture duration is fixed at 4 seconds from the UI and helper hard-caps it at 5 seconds;
- capture is limited to 50 packets and current configured syslog listen ports;
- packet payload output is not requested (`tcpdump` header summaries only);
- no user-supplied tcpdump expression, executable, interface, port, or shell command is accepted;
- one capture may run at a time in the dashboard process;
- the dashboard invokes a fixed root-owned helper with `sudo -n`, never `shell=True`;
- `install-services.sh` copies the helper to `/usr/local/libexec/mini-siem-syslog-capture`, writes root-only `/etc/mini-siem/syslog-capture.json`, and installs `/etc/sudoers.d/mini-siem-troubleshoot`;
- the dashboard service account cannot modify the root-owned helper or its helper configuration.

This feature proves network arrival only. A positive packet capture does not prove parser success or database persistence.


## PostgreSQL Runtime Migration Boundary

Status:
IMPLEMENTED

Runtime identities must not repair or initialize database schema.

Rules:
- listener runtime role must not execute DDL
- dashboard runtime role must not execute DDL
- schema initialization is an owner/migrator operation
- migrations must complete before runtime services start

Startup model:

owner/migrator
    |
    v
schema and migration ledger ready
    |
    v
listener/dashboard runtime identities start


## SQLite to PostgreSQL Migration Invariant

SQLite to PostgreSQL migration must not blindly copy `schema_migrations` as business data.

The target PostgreSQL database must first be prepared by the target-version owner migration path.

Data migration may copy:
- logs
- alerts
- configuration data
- required business records

Migration history belongs to the target application schema version.

## 2026-09-13 — Web Console Security/Runtime + Archive/Maintenance Observability

Canonical parent baseline: `mini_siem_postgres_migration_boundary_docs_sync_2026-09-13.zip`.
The previously generated `mini_siem_webconsole_observability_2026-09-13.zip` was rejected as a development parent after inspection showed stale lineage and runtime `initialize()` calls. This slice was rebuilt from the canonical privilege-boundary baseline instead.

Implemented:
- Cross-process listener health is persisted in `runtime_stats` and rendered on Health. Listener heartbeat includes READY/DEGRADED/FAILED state, ingest state, direct-worker mode, uptime, processed/failed/dropped counters, last event, and heartbeat age. A stale heartbeat is shown as STALE; the dashboard does not restart the listener automatically.
- PostgreSQL Security & Schema Readiness is read-only and admin-only. It reports the effective dashboard DB role, raw-log SELECT/INSERT/DELETE/UPDATE/TRUNCATE capabilities, guard-trigger count, migration-ledger write capability, maintenance-role inheritance, current/expected migration versions, and pending versions.
- Setup no longer recommends killing/relaunching `listener.py`; it uses `sudo systemctl restart mini-siem-listener`, preserving the service account and DB credential overlay.
- Archive & Maintenance Health is read-only and admin-only. It shows archive policy, sealed segment/event totals, latest segment, last checksum verification, maintenance timing/errors, and the maintenance privilege boundary.
- Archive execution remains CLI/maintenance-only; the Web Console has no endpoint that runs archive, checksum repair, raw-log eviction, privilege changes, or migrations.
- PostgreSQL archive catalog mutation is restricted to the maintenance identity. Listener/dashboard identities are SELECT-only on `archive_segments` and `archive_occurrence_catalog`; maintenance may SELECT/INSERT/UPDATE/DELETE but not TRUNCATE.
- Added missing portable foundations used by the existing archive code: `runtime_stats`, `archive_segments`, `archive_occurrence_catalog`, `Connection.executemany()`, `Connection.rollback()`, and conservative Storage batch/commit/rollback/close helpers.

Schema/migration impact:
- Migration ledger now has 26 versions. Versions 22-26 create `runtime_stats`, archive catalog tables, and their indexes.
- PostgreSQL runtime identities still perform no DDL. Owner/migrator must apply the new migrations before services start.
- After owner migration, rerun `tools/postgres_privilege_boundary.py` so the archive-catalog SELECT-only/maintenance-write boundary is applied to the new tables.

Validation performed for this slice:
- New observability/privilege/troubleshoot targeted set: 15 passed, 0 failed.
- Existing `tests/test_evidence_archive_phase6.py`: 5 passed, 2 failed. The two failures are pre-existing baseline debt outside this slice: missing `hourly_log_stats` rollup infrastructure and missing legacy `_record_query_telemetry_safe` dashboard symbol. They are not counted as passed.
- SQLite live archive smoke: sealed segment creation, checksum verification, catalog entry, `archive_status`, and `archive_verify_status` all succeeded.

Final local validation update for this slice: broader targeted regression is 30 passed / 0 failed; static security scan is 0 findings; Python source compile, Health-page JavaScript syntax, and service-shell syntax pass. Full repository pytest is not green/complete in this environment because Flask/Werkzeug are absent and collection stops on 3 modules.

## 2026-09-13 — Operational Readiness & Incident Diagnostics

Implemented on the canonical `mini_siem_archive_maintenance_observability_2026-09-13.zip` baseline.

Delivered implementation:
- `operational_diagnostics.py` aggregates Database, Listener, Ingest, PostgreSQL security/schema, Archive/Maintenance, syslog socket and storage evidence into a read-only incident view with HEALTHY/WARNING/DEGRADED/FAILED/UNKNOWN states and dependency edges.
- `GET /api/diagnostics/status` exposes the current read-only snapshot to administrators; `POST /api/diagnostics/run` performs the same bounded checks and records `DIAGNOSTIC_RUN` in the audit trail.
- `POST /api/support/bundle` creates an in-memory, allow-listed support tarball and records `SUPPORT_BUNDLE_CREATED`. Credential files, passwords, API keys, private keys and raw event payloads are excluded. Raw service journals are intentionally omitted because listener stdout may contain event-message excerpts.
- Listener runtime heartbeat now keeps bounded per-peer counters (`accepted`, `failed`, `last_seen`; maximum 64 peers) without event payloads. Setup > Troubleshoot uses them together with packet arrival and peer-IP storage correlation to report Network -> Listener -> Parser -> Storage -> Search stages.
- Health Web Console now exposes Incident Diagnostics and dependency state; Setup includes a Support Bundle workflow.

Security/architecture invariants retained:
- Web diagnostics are observation-only. They cannot restart services, run owner migrations, repair schemas, change PostgreSQL privileges, execute archive maintenance or obtain maintenance credentials.
- PostgreSQL runtime identities continue to use `ensure_runtime_ready()` rather than schema initialization.
- Support artifacts use a fixed allow-list and secret minimization; arbitrary file paths/commands are not accepted from Web input.

Initial verification in the build environment: targeted operational/security/database suite 31 passed, static security scan 0 findings. Full repository status and artifact-level packaging results are recorded in TESTING.md and the delivery manifest.


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Phase 12.3 — Backup / Restore Readiness

Status: IMPLEMENTED_TESTING_DEFERRED

Added backup manifest/checksum validation workflow. Runtime identities do not perform schema migration or repair during restore.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED
