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

Status: `IMPLEMENTED_TESTING_DEFERRED` (live PostgreSQL validation deferred).

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

Status: `IMPLEMENTED_TESTING_DEFERRED` (host-integration validation required).

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
- Migration ledger now has 30 versions. Versions 22-26 create `runtime_stats`, archive catalog tables, and their indexes; versions 27-30 create the AI usage audit table and indexes.
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
## 2026-09-18 — OpenAI Responses API and AI provider hardening

Implemented:
- `LLMClient` supports `auto`, `responses`, and `chat_completions`; `api.openai.com` auto-selects Responses while local/compatible endpoints preserve Chat Completions.
- Responses calls use `store=false`, bounded retry/backoff for 429/5xx, `x-request-id`, and generated `X-Client-Request-Id`.
- AI API keys are encrypted with the existing authenticated `secretbox` primitive using a new external master file rather than a DB-resident master. Legacy plaintext AI keys migrate in place.
- Added metadata-only `ai_usage_audit` plus admin read API `GET /api/ai/usage`; no prompt, evidence, output text, or API key is written to usage audit.
- PostgreSQL privilege boundary grants dashboard INSERT-only mutation on AI usage evidence and denies UPDATE/DELETE/TRUNCATE to runtime application identities.
- Migration ledger advances from 26 to 30; PostgreSQL owner/migrator must apply versions 27-30 before runtime startup, then privilege provisioning must be rerun.
- Added loopback protocol integration tests plus an opt-in live OpenAI smoke test.

The existing installer owner/runtime PostgreSQL separation changes are retained.


### Validation evidence for this change set

- targeted AI/provider/security tests: 33 passed, 1 intentionally skipped live-provider smoke;
- broad dependency-available A/B regression: parent and patched trees have the same 32 inherited failures, while passing tests increase from 70 to 79;
- changed Python compile, shell syntax, AI JavaScript syntax, fresh DB migration/key migration, and static security scan passed;
- Flask-dependent regression, live OpenAI, and live PostgreSQL privilege verification remain deferred.

## 2026-09-18 — P0 source truth repair + P1 PostgreSQL fresh-bootstrap foundation

Status: `IMPLEMENTED_TESTING_DEFERRED` overall.

Canonical parent inspected: `mini_siem_openai_responses_hardening_2026-09-18.zip`, SHA-256 `dfb2776c069b32b633f99b0770e303a8971d813aaa33af198667f795d1e8029f`.

### P0 findings and changes

- Parent whole-tree `compileall` reproduced 12 syntax failures from prose stored in Phase 13 `.py` files.
- A further 7 Phase 13 `.py` files were valid syntax but only design/reference constants or unbound-name placeholders; they were also not usable implementation.
- All 19 Phase 13 pseudo-code files were reclassified as Markdown `*_REFERENCE.md` material. Phase 13 remains `PLANNED`.
- Added `PHASE13_PLACEHOLDER_RECLASSIFICATION.md` to preserve the source-truth decision.
- Added `tools/build_source_artifact.py` so package integrity is an executable gate rather than a checklist only. It rejects `.git`, caches, bytecode, symlinks and runtime secret/state files; generates the complete per-file manifest; validates required files/size/shebang; builds ZIP; re-extracts it cleanly; verifies CRC/traversal/symlinks; validates Python/shell/JavaScript syntax in the extracted artifact; and compares every packaged source file by size/SHA-256.

### P1 fresh PostgreSQL bootstrap

- Added `tools/postgres_bootstrap.py` with explicit `fresh` and `inspect-existing` modes.
- Customer PostgreSQL bootstrap credentials are prompt/environment input only and are never written to mini-SIEM config.
- `configure-db.py` now records a non-secret PostgreSQL endpoint/database only; it does not ask for or persist a runtime/DBA username/password.
- Fresh bootstrap creates/checks a dedicated `minisiem_owner`, creates/checks the target database, runs `db.initialize()` using the owner identity, provisions split runtime roles, writes component credential overlays, and verifies each role through `db.ensure_runtime_ready()`.
- The migration owner remains `NOCREATEROLE`. `postgres_privilege_boundary.py` was refactored so runtime role creation/rotation can use a separate temporary role-admin connection while object/default-privilege grants execute as the schema owner.
- Fresh bootstrap refuses unexpected existing DB ownership and refuses to adopt a target containing public/application objects. This prevents a fresh-install path from becoming an implicit upgrade/destructive ownership migration.
- `inspect-existing` is read-only and reports DB owner, public-schema owner, object owners, migration versions, split-role presence, local credential overlays and systemd-unit presence. It explicitly performs no owner transfer/recreation.
- `install-services.sh --bootstrap-postgres` invokes fresh bootstrap only when explicitly requested. PostgreSQL service installation now refuses a missing split privilege boundary and validates listener/dashboard schema readiness before systemd unit installation/start.

### Validation evidence collected in this environment

- Parent dependency-available comparison suite: **82 passed, 41 failed, 1 skipped**.
- Patched dependency-available comparison suite after new tests: **92 passed, 41 failed, 1 skipped**. The existing 41 failure set remains baseline debt; it includes unavailable Flask imports plus inherited Phase 3-6/performance/UI/search drift. This changeset does not claim those failures are fixed.
- Focused P0/P1/PostgreSQL tests: **21 passed**.
- Repository-wide `python -m compileall`: **PASS** after Phase 13 reclassification.
- Shell syntax: **PASS** for 4 shell scripts.
- JavaScript syntax: **PASS** for 1 standalone JavaScript file when Node is available.
- Static security scan: **0 findings across 29 scanned root Python files**.
- Full pytest collection remains **DEFERRED/INCOMPLETE** in this environment: 134 tests collect, but collection stops with 3 errors because Flask/Werkzeug are not installed.
- Live PostgreSQL, systemd, browser, OpenAI, backup/restore and sustained performance gates remain `NOT_RUN`/deferred; no `TESTED` or `RELEASED` product claim is made.

### Next engineering slice

Complete P1B: controlled existing/legacy PostgreSQL upgrade to the split-owner/runtime boundary, including backup evidence, explicit ownership-transfer plan/execution, interrupted migration recovery, idempotency, rollback/recovery, and credential rotation/re-provision. Do not begin Phase 13 feature implementation before the baseline/reliability sequence is complete.

### P0 packaging integrity gate result

P0 source-truth/packaging repair is `TESTED` as a bounded scope. A complete-source ZIP was built and independently extracted; ZIP CRC, path traversal, symlink, required-file/size/shebang, extracted Python/shell/JavaScript syntax, and complete source-to-extracted SHA-256 parity checks passed. The extracted artifact then passed the 21-test focused P0/P1/PostgreSQL smoke suite. This does not promote P1, the overall product, or the release to `TESTED`/`RELEASED`; live and full-regression gates remain deferred.

## 2026-09-18 — Full repository placeholder truth alignment

- Reclassified 6 non-implementation runtime/qualification `.py` placeholders as Markdown contracts.
- Removed 6 no-op `assert True` tests from pytest collection and replaced them with explicit required-coverage documents.
- Reclassified 28 migration/release executable-shaped scaffolds as `PLANNED` documentation because they did not perform the actions implied by their filenames.
- Kept the Sophos adapter skeleton only as an explicit example with `EXAMPLE_ONLY = True`.
- Added `PLACEHOLDER_TRUTH_ALIGNMENT.md`, machine-readable `PLACEHOLDER_TRUTH_INVENTORY.json`, `tools/check_placeholder_truth.py`, and regression tests for the truth gate.
- This work is source/status alignment, not implementation of the removed capabilities. Overall product status remains `IMPLEMENTED_TESTING_DEFERRED`.

### Placeholder-alignment validation evidence

- `python tools/check_placeholder_truth.py`: PASS; 40 reclassified executable/test paths remain absent and the one intentional incomplete example is explicitly marked.
- repository `compileall`: PASS.
- shell `bash -n`: PASS.
- standalone JavaScript syntax: PASS where Node is available.
- static security scan: 0 findings across 29 root Python files.
- focused placeholder/P0/P1 suite: 17 passed.
- dependency-available suite: 88 passed, 41 failed, 1 skipped; the 41 failures are inherited baseline debt. The prior 92-pass count included six no-op `assert True` tests; those six false passes were removed and two real truth-gate tests were added, producing the truthful 88-pass count.
- full pytest collection remains incomplete because Werkzeug/Flask are unavailable for three modules in this environment.

- extracted complete-source artifact placeholder/P0/P1 focused smoke: 17 passed; artifact placeholder-truth gate: PASS.


## 2026-09-18 — OpenAI egress hardening convergence

Status: `IMPLEMENTED_TESTING_DEFERRED` overall. The bounded mocked/provider hardening scope is locally tested; live OpenAI qualification is still deferred.

Implemented in this convergence slice:
- external AI mode validates the endpoint before use and requires HTTPS by default; insecure HTTP is available only for an explicitly enabled loopback development endpoint (`MINISIEM_AI_ALLOW_INSECURE_LOOPBACK_EXTERNAL=1`);
- outbound external evidence has configurable `strict`, `identifiers`, or `none` redaction, with `strict` as the default; redaction runs immediately before provider payload construction;
- strict redaction masks IPv4/IPv6, labelled hostnames and identity-like values/email addresses, and removes the standard evidence formatter's raw log-message/alert-description free text;
- Responses API HTTP-200 bodies with `status=failed` or `status=incomplete` fail closed with metadata-only usage/error evidence;
- OpenAI Chat Completions compatibility uses `max_completion_tokens`, while generic/local compatible servers retain `max_tokens`;
- transient URL/connection/timeout failures now use the same bounded retry discipline as retryable HTTP status codes, with a total call-time budget;
- `/api/ai/test` and the live qualification probe use a 128-token output budget to avoid false negatives with reasoning-capable models;
- `/ai` exposes the external evidence-redaction control and makes the HTTPS/redaction egress boundary visible to administrators.

Validation in this environment:
- OpenAI mocked/provider tests: **19 passed, 1 skipped** (the skip is the opt-in live test);
- AI/progressive investigation focused suite: **41 passed, 1 skipped**;
- dependency-available repository suite excluding the three uncollectable Flask/Werkzeug modules: **98 passed, 41 failed, 1 skipped** after this slice; the 41 failures are inherited baseline debt, not new OpenAI failures;
- full `pytest` collection remains incomplete because `flask`/`werkzeug` are unavailable for `tests/test_admin_bootstrap.py`, `tests/test_dashboard_routes.py`, and `tests/test_log_search_logic.py`;
- repository `compileall`, shell syntax, AI inline JavaScript syntax, placeholder-truth gate, and static security scan passed; static scan reports **0 findings / 29 scanned root Python files**;
- opt-in live `gpt-5.6-luna` Responses qualification was attempted conditionally, but `OPENAI_API_KEY` is absent in this execution environment, so the live call is **NOT_RUN / DEFERRED**.

No product-level `TESTED` or `RELEASED` claim is made.


Artifact-level verification for this slice: clean extraction, ZIP CRC/path-traversal/symlink checks, required-file and syntax gates, complete source-to-extracted SHA-256 parity, placeholder-truth gate, and the extracted AI/progressive focused suite all pass; extracted focused result is **41 passed / 1 skipped**. The skip remains the live OpenAI test because no API key is present.

## 2026-09-19 — PostgreSQL Event Storage v2

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Implemented source:
- raw `logs/log_fields` evidence remains intact while PostgreSQL ingest
  transactionally appends a typed `security_events` projection;
- native `TIMESTAMPTZ`, `INET`, integer-port and `JSONB` query dimensions;
- monthly `RANGE(event_time)` partitions, default safety partition, bounded
  SECURITY DEFINER pre-creation function, and daily split-role systemd timer;
- composite entity+time indexes, JSONB GIN, message FTS GIN and event-time BRIN;
- exact IP/CIDR, prefix host/destination and explicit-contains query semantics;
- normalized dynamic-field exact/prefix/contains semantics via `value_norm`;
- minimal `assets`/`identities` observation model plus `security_event_context`;
- PostgreSQL correlation windows read the typed query plane; higher-level
  correlation grouping remains Python and is not claimed SQL-native;
- archive MOVE evicts the typed hot projection before raw hot evidence;
- split roles explicitly constrain Event Storage mutation and future owner
  default table privileges are SELECT-only so new partitions fail closed;
- owner-only idempotent migration/backfill/qualification tooling;
- PostgreSQL Phase 4 synthetic ingest now uses the real storage batch path and
  cannot bypass the typed projection.

Local regression comparison using the same dependency-available suite (three
Flask/Werkzeug-uncollectable modules excluded): parent **98 passed / 41 failed /
1 skipped**; current **109 passed / 37 failed / 1 skipped**; new failing node IDs:
**0**; four inherited normalization/query-contract failures are fixed.

Live PostgreSQL migration/backfill, partition pruning/EXPLAIN, split-role
privilege behavior, archive eviction and restart/readiness remain
`NOT_RUN/DEFERRED` because no usable PostgreSQL server/credentials are available
in this execution environment.  Do not promote this slice to `TESTED` from
source/contract evidence alone.

Repository-wide source gates for this slice:
- `python -m compileall`: PASS;
- shell syntax: 4/4 PASS; standalone JavaScript: 1/1 PASS;
- placeholder truth gate: PASS;
- static security scan: 0 findings / 30 scanned Python files;
- bounded source secret-pattern scan: 0 findings / 325 text files;
- Event Storage/PostgreSQL focused suite: 27 passed;
- full pytest collection remains BLOCKED/INCOMPLETE at exactly three modules because Flask/Werkzeug are unavailable in this environment.

Artifact smoke for this slice: clean extraction passed and the same 27-test
Event Storage/PostgreSQL focused suite passed from packaged source.  Packaging
integrity includes CRC/traversal/symlink/junk checks and full per-file parity.
This does not replace the deferred live PostgreSQL qualification.

## 2026-09-19 — Split fresh-install / existing-upgrade entry points

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Installation orchestration is now deliberately split:

- `fresh-install.sh` is the only operator entry point for a new installation. It refuses existing systemd/runtime state and is the only path allowed to invoke the internal PostgreSQL fresh-bootstrap mode.
- `upgrade-existing.sh` is the only operator entry point for an existing installation. It must run from a separately extracted new source tree, stages/cuts over at the stable target path, retains the old tree for rollback, preserves deployment config/state, and never calls fresh bootstrap.
- `tools/postgres_upgrade_existing.py` upgrades an existing **split-role** PostgreSQL deployment using a temporary owner credential. It tightens owner default privileges before DDL, performs additive owner migrations + idempotent Event Storage v2 backfill, refreshes grants without CREATEROLE, and preserves all existing runtime-role passwords/credential files.
- `tools/postgres_privilege_boundary.py --preserve-existing-credentials` is grants-only. It validates the existing role topology and never creates roles or rotates passwords.
- Legacy shared owner/runtime PostgreSQL deployments are still a separate controlled migration problem and are not auto-adopted by `upgrade-existing.sh`.

Local contract/syntax tests do not promote this workflow to `TESTED`; live PostgreSQL/systemd/rollback/reboot qualification remains required.

Dual-entrypoint local verification checkpoint: focused install/PostgreSQL/Event Storage/build suite 27 PASS; broad same-suite current 112/37/1 versus parent 109/37/1 with zero new failing node IDs. Compileall, 6 shell syntax checks, JavaScript syntax, placeholder truth and bounded secret scan pass. Full pytest collection remains blocked by the same three missing Flask/Werkzeug modules. Live install/upgrade qualification is still deferred.

Dual-entrypoint artifact smoke checkpoint: clean-extracted complete source passed the 27-test focused suite plus packaging integrity. Final artifact is rebuilt after this evidence update and revalidated before handoff.


## 2026-09-19 — Existing PostgreSQL upgrade owner-discovery hardening

Status: `IMPLEMENTED_TESTING_DEFERRED`. This patch is intentionally limited to the existing-installation upgrade path; `fresh-install.sh` and fresh PostgreSQL bootstrap semantics are unchanged.

A live NAS upgrade exposed a legacy-owner compatibility bug: the existing database was owned by `minisiem`, while the upgrader guessed the fresh-install-only role name `minisiem_owner`. The upgrade now discovers the real database owner through the already-working installed dashboard runtime credential and installed project Python, so it does not depend on system Python having `psycopg2` and it does not invent an owner role. The resolved owner is used consistently for backup and owner migration.

The same NAS also had PostgreSQL 18 with host `pg_dump` 16. Existing upgrade now checks server/client major versions, prefers a compatible host client, and for localhost Docker-published PostgreSQL can use the matching container `pg_dump` and `pg_restore` to stream and verify the pre-upgrade custom-format archive. Dump stderr is preserved as evidence.

Rollback and successful cutover now invoke `install-services.sh` from the target working directory so `python -c "import db"` resolves the restored/installed tree rather than the operator's extraction directory. Upgrade failures record the failing stage and backup/client metadata in `upgrade-failure.json`.

## 2026-09-19 — Existing PostgreSQL ledger-driven migration fix

Status: `IMPLEMENTED_TESTING_DEFERRED`. Existing PostgreSQL upgrades no longer call the generic `db.initialize()` bootstrap/current-schema path. `tools/postgres_upgrade_existing.py` now advances an existing populated `schema_migrations` ledger explicitly: pending legacy migrations through v30, normalized `log_fields.value_norm` repair, Event Storage v2 DDL statement-by-statement, then readiness markers 31-33 only after all required DDL succeeds. Each owner DDL statement is printed to the terminal with its stage and the original PostgreSQL error on failure. Fresh-install code and `fresh-install.sh` are unchanged.

Local evidence: focused upgrade/PostgreSQL/Event Storage suite 27 PASS / 0 FAIL; broad dependency-available comparison parent 112 PASS / 37 FAIL / 1 SKIP vs current 116 PASS / 37 FAIL / 1 SKIP, with 0 new failing node IDs. Live NAS migration 26→33 remains NOT_RUN/DEFERRED after this patch.


## 2026-09-19 — Executable-mode packaging repair

The complete-source ZIP builder now treats executable permission metadata as an artifact-integrity requirement. Intended operator entrypoints and shebang tools are emitted as Unix regular files with mode `0755`, independent of the source-tree mode, and the artifact verifier checks both ZIP metadata and a real standard-`unzip` extraction. This is packaging-only; `fresh-install.sh` behavior and fresh PostgreSQL bootstrap logic are unchanged.


## 2026-09-20 — Fresh-install database-intent boundary hardening

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Fresh installation now has an explicit two-stage operator contract: run
`configure-db.py` first, then `fresh-install.sh`. The fresh installer consumes
the exact generated `db-config.json`; it no longer deletes/recreates database
configuration or silently selects SQLite. `install-services.sh` also fails
closed when the database config is missing, malformed, or unsupported, and
`db.load_config()` now fails closed when an explicit `--db-config` path is
missing or invalid. This makes PostgreSQL selection irreversible through the
installer/runtime path: a PostgreSQL error stops installation rather than
changing engines.

PostgreSQL fresh ordering is bootstrap roles/database -> `minisiem_owner`
DDL/migrations -> schema/ownership verification -> split runtime credentials ->
runtime readiness -> systemd installation/start. Customer DBA and owner secrets
are not persisted in runtime configuration. `upgrade-existing.sh` is unchanged.
Live NAS PostgreSQL/systemd acceptance remains `NOT_RUN/DEFERRED`.


### 2026-09-20 local validation evidence

- PostgreSQL/config/install/Event Storage/build focused regression: **39 passed / 0 failed**.
- Disposable two-stage harness: `configure-db.py` PostgreSQL selection -> exact `db-config.json` preservation -> `fresh-install.sh` -> `install-services.sh --bootstrap-postgres`: **PASS**.
- `upgrade-existing.sh`: byte-for-byte unchanged from parent, SHA-256 `f1bf5433eac3533c0936cf1ea15c768da3a8db68e1c03acdc82b70e32ed07286`.
- repository `compileall`: PASS.
- shell `bash -n`: PASS.
- placeholder truth gate: PASS.
- static security scan: **0 findings / 30 root Python files**.
- live NAS PostgreSQL role/database/schema/systemd/reboot acceptance: **NOT_RUN/DEFERRED**.

### Fresh PostgreSQL schema initialization percent-SQL fix — 2026-09-21

Fresh PostgreSQL owner initialization failed when static Event Storage v2 DDL containing PostgreSQL format tokens such as `%I`/`%L` was sent through the parameterized psycopg2 execution path. The trusted schema/migration path now uses the existing raw SQL executor for static PostgreSQL DDL/migration statements, while runtime parameterized queries continue to use `execute()`.

The regression is covered by `tests/test_db.py::test_postgres_initialize_executes_percent_ddl_as_raw_sql`, which verifies both schema and migration static SQL containing literal percent signs bypass parameter parsing.

## 2026-09-23 — Product-boundary and AI entity-expansion alignment

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Source review corrected several roadmap assumptions rather than creating duplicate subsystems:

- Evidence hot/cold handling is already implemented by `archive.py`; future work is measured PostgreSQL-scale qualification, not a greenfield archive feature. Additional object-storage/Parquet tiers are demand-driven only.
- Generic ticket integration already exists through `workers.TicketWorker` and carries related log IDs plus AI analysis. The specific remaining scheduled-playbook gap is report finding -> alert creation; alert -> ticket dispatch already exists.
- Full SOAR-style playbook governance is not required for the current 14 correlation/detection playbooks because they are investigation/detection content rather than destructive response automation.
- AI investigation continues to keep raw evidence in SIEM storage/archive; no duplicate investigation evidence store is introduced.
- Progressive AI context now supports bounded deterministic multi-hop entity expansion. Short remains on the trigger entity; Medium may follow one confirmed peer that later appears as a source; Long may follow two hops. Expansion is bounded (`short`: depth 0/entity 1; `medium`: depth 1/entity 6; `long`: depth 2/entity 12), excludes `peer_ip` from pivot discovery because it is commonly the collector/firewall sender, and keeps all query authority in the application rather than the LLM.
- Existing same-entity cross-source matching is preserved: admitted IPs match source, destination, peer, and indexed endpoint/source/destination fields regardless of severity.

Tests added in `tests/test_warning_ai_context.py` prove that a destination which later becomes a source is promoted at Medium, that the next hop appears only at Long, passive destinations are not promoted, unrelated traffic stays out, and expansion metadata/limits are exposed to the prompt for traceability.


## 2026-09-23 — `/correlate` Manual Correlate -> Investigate workspace

Status: `IMPLEMENTED_TESTING_DEFERRED`.

The former ad-hoc/manual correlation form on `/correlate` is replaced by a
manual IP **Investigate** workspace while preserving the correlation engine and
`/api/correlate` endpoint for playbooks/API compatibility.

Implementation contract:

- analyst supplies one IPv4/IPv6 root entity;
- a discrete Short/Medium/Long slider maps to concrete retrospective windows
  ending now: 30 minutes / 90 minutes / 5 hours;
- a separate 0-4 hop slider controls actual server-side pivot depth;
- manual scope uses the generic investigation profile span because there is no
  alert type/timestamp to classify; alert-driven AI triage remains unchanged;
- pivot admission reuses the existing deterministic destination->later-source
  rule; `A -> B` does not admit B unless B subsequently appears as `source_ip`;
- admitted entities continue to match evidence in source, destination, peer, or
  indexed endpoint/source/destination fields;
- `peer_ip` remains evidence-only for pivot discovery;
- results expose the effective window, entity cap/depth, admitted entities,
  confirmed relationship/proof event IDs, candidate/evidence counts and bounded
  event rows;
- manual investigations are written to the existing audit log as
  `manual_ip_investigation`; no duplicate evidence store is created.

The server implementation is `ai_soc.gather_ip_investigation()` and
`POST /api/investigate/ip`. `_discover_pivot_entities()` now accepts bounded
manual overrides while retaining the existing stage defaults for AI triage.

Local verification for this slice: manual Investigate + progressive AI/OpenAI
54 PASS; DB/Event Storage/PostgreSQL/installer/source-builder 40 PASS;
placeholder truth 2 PASS; compileall, all shell syntax, and Correlate inline JS
syntax PASS. Archive focused check remains 6 PASS / 2 inherited known failures
already present in the parent baseline. Flask/browser live route validation is
deferred because Flask is unavailable in the packaging environment.
Static security scan after the manual Investigate query-path change reports 0 findings / 30 root Python files; all entity/time values remain bound parameters and only fixed application SQL fragments are assembled.

## 2026-09-23 Priority hardening + Alert Lifecycle slice

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Implemented on top of `mini_siem_manual_investigate_slider_2026-09-23.zip`:

1. **PostgreSQL bootstrap preflight** — the fresh bootstrap connects/authenticates
   first, verifies PostgreSQL `current_user`, and requires superuser or both
   `CREATEDB` and `CREATEROLE` before any bootstrap DDL. Connectivity/auth and
   privilege failures are returned as operator-safe diagnostics rather than raw
   psycopg2 tracebacks. The customer bootstrap password is not persisted.
2. **Interrupted fresh-install resume** — `fresh-install.sh --resume` accepts
   only the same checkpointed interrupted fresh install. State includes target,
   backend, config SHA-256, selected source fingerprint, phase and status.
   PostgreSQL owner/runtime secrets are stored only in a root-only transient
   resume file, reused unchanged across resume, and removed only after
   `OPERATIONAL`. Completed earlier phases may be revalidated idempotently
   without regressing a later checkpoint. Operational installs still require
   `upgrade-existing.sh`.
3. **Listener/systemd least privilege** — listener runs as non-login
   `siem-listener` with only `CAP_NET_BIND_SERVICE`; dashboard remains `siem`;
   PostgreSQL partition maintenance runs as `siem-maintenance`. Credential-file
   readability is component-separated. Listener uses a bind-only bounding set;
   dashboard/maintenance explicitly set `NoNewPrivileges=true` and an empty
   capability bounding set. Existing systemd sandbox controls remain enabled.
4. **Alert Lifecycle** — durable states `new`, `acknowledged`, `investigating`,
   `resolved`, `closed`; controlled reopen; assignee; actor/timestamp/note;
   append-only workflow history; analyst API/UI; audit event. A review caught
   and fixed a cross-dialect migration bug so PostgreSQL workflow-event IDs use
   `BIGSERIAL` rather than SQLite-style `INTEGER PRIMARY KEY`.
5. **Scheduled playbook finding -> alert** — weekly/monthly report findings are
   converted into the normal alert table and therefore inherit AI triage,
   Alert Lifecycle and existing TicketWorker delivery. Conversion is
   report-scoped/idempotent, and an hourly scheduler pass heals a report that
   committed before its alerts were emitted.

Product-boundary decision: mini-SIEM will **not** become a full case-management
or SOAR platform. Existing outbound ticket/SOAR integrations are the handoff
boundary. `SOC_CASE_WORKFLOW.md`, broader entity graph, consolidated
investigation workspace, dedicated rule-management UX and additional SOC
metrics remain revisit/reference topics rather than current implementation
commitments.

Local evidence before packaging: the five focused feature suites pass 25/25.
The dependency-available broad comparison has the exact inherited 37 failing
node IDs: parent 137 PASS / 37 FAIL / 1 SKIP versus current 159 PASS / 37 FAIL /
1 SKIP. Full collection is still blocked at the same three modules because this
offline runner lacks Flask/Werkzeug; dependency installation was attempted but
network/DNS access is unavailable. Live Linux/systemd/PostgreSQL execution
remains `NOT_RUN/DEFERRED`.


## 2026-09-23 SQLite FTS5 optional-capability hardening

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Canonical parent: `mini_siem_priority_hardening_alert_lifecycle_2026-09-23.zip` (SHA-256 `2bb230f6697469a1c4ff8f225b651e48853a1b6e7fb46db79578c296c7ef64ba`).

The startup/search defect where SQLite FTS5 was effectively mandatory is fixed
without expanding scope. `db.py` now keeps the SQLite base schema independent
from the FTS5 virtual table. `fts5_available()` performs a real ephemeral TEMP
FTS5 virtual-table probe instead of depending only on compile-option metadata.
`initialize()` creates `logs_fts` and all three maintenance triggers only when
that probe succeeds; FTS rebuild/backfill is gated by the same capability.
When capability is unavailable on a database that previously used FTS5,
`logs_ai`, `logs_ad`, and `logs_au` are dropped so ingest/update/delete does not
retain a hidden dependency on a module the current SQLite runtime cannot load.
The virtual-table metadata itself is preserved so later FTS5-capable startup can
recreate triggers and rebuild normally.

`dashboard.py` now selects `sqlite_fts5` only when the request connection passes
the runtime probe. `sqlite_like` emits escaped, case-insensitive `LIKE` / `NOT
LIKE` predicates and never references `logs_fts`. Exclusion-only FTS queries
continue to use the LIKE path because FTS5 cannot express a useful standalone
NOT query.

Regression coverage added in `tests/test_sqlite_fts_optional.py` and
`tests/test_text_search_backend.py`: fresh initialization with FTS forced
unavailable; no FTS table/trigger dependency; ingest after no-FTS startup;
functional dashboard-generated LIKE search; existing FTS-created database
reopened with capability unavailable; trigger detachment and continued ingest;
runtime-probe behavior; normal FTS MATCH synchronization; and explicit
`sqlite_like` query-builder coverage. The existing `test_log_search_logic.py`
fixture already forces `fts5_available=False`, so once Flask/Werkzeug is present
it is the end-to-end regression for the previously dead fallback path.

Validation in this environment: FTS-focused 6 PASS / 0 FAIL; prior five-suite
priority hardening plus FTS coverage 31 PASS / 0 FAIL; canonical DB/Event
Storage/PostgreSQL/installer/artifact-builder regression 51 PASS / 0 FAIL; broad
dependency-available suite 166 PASS / 37 inherited FAIL / 1 SKIP, with the same
37 failing node IDs and 0 newly introduced failures. Full collection remains
blocked at the same Flask/Werkzeug-dependent modules. Live qualification on a
SQLite library genuinely built without FTS5 remains deferred, so overall status
stays `IMPLEMENTED_TESTING_DEFERRED`.


## 2026-09-23 sequential source-gap closure — P1B / P5 / P6 / P8 / P13

Status: `IMPLEMENTED_TESTING_DEFERRED`

Processed in the requested order without expanding the mini-SIEM product boundary.

1. **P1B legacy PostgreSQL conversion:** added `tools/postgres_legacy_split_migration.py` and integrated it into `upgrade-existing.sh` after verified pre-upgrade backup evidence. The existing DB owner is retained as the migration/schema owner; split listener/dashboard/maintenance identities are provisioned and verified; owner/bootstrap secrets are not persisted.
2. **P5 backup/restore:** added `tools/postgres_backup_restore.py` plus manifest helpers. Backup is `pg_dump -Fc` + archive validation + SHA-256 manifest. Restore is fail-closed to a new DB, disables archive owner/ACL replay, verifies required schema/migration ledger and cleans an incomplete new DB on failed verification.
3. **P6 performance:** added `performance_runtime_v2/qualification_runner.py` over real parser/ingest/query/correlation paths with EPS, percentile latency, RSS/storage growth and PostgreSQL connection evidence. No thresholds means `MEASURED_NO_THRESHOLDS`; 24h/72h modes are supported but not claimed executed.
4. **P8 CEF:** wired CEF into `parse_syslog()`, completed escaped header/extension handling and normalized CEF severity/event schema, indexed custom CEF fields, and restored executable listener->DB->indexed-field->correlation regression coverage.
5. **P13 release engineering:** replaced scaffold release/provenance helpers with a fail-closed gate that verifies source/artifact/docs/qualification/provenance and requires explicit human approval only after technical qualification passes.

Local implementation evidence: P1-focused 32 PASS; P5-focused 14 PASS; P8/placeholder 7 PASS; P13/artifact-builder 9 PASS; broad dependency-available comparison current **187 PASS / 37 FAIL / 1 SKIP** versus parent **166 PASS / 37 FAIL / 1 SKIP**, with the exact same 37 failing node IDs and therefore **0 new failing nodes**. P6's new focused tests pass; inherited legacy performance-contract failures remain part of the unchanged parent failure set.

Deferred truth: no live legacy PostgreSQL conversion/restore drill, production PostgreSQL/systemd/SELinux/browser/provider/network qualification, agreed production performance thresholds, or 24h/72h sustained run has been completed in this slice. P12 remains not complete and the product is not `RELEASED`.


## 2026-09-23 — P3 systemd host-hardening source audit

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Source audit found two real least-privilege defects behind the previously deferred P3 live gate. First, PostgreSQL installs left the application root group-writable and the listener sandbox explicitly allowed source-tree writes. Second, the listener was a member of the same `minisiem` group that owned the dashboard PostgreSQL credential, contradicting the installer's own cross-component credential-denial check.

Implemented corrections: dedicated `minisiem-dashboard` credential group; `minisiem` reduced to shared code/read-state use; dashboard/listener/maintenance credentials owned by their component groups; PostgreSQL source tree made non-writable to runtime identities; enabled PostgreSQL archive state rejected when it resolves inside source; external archive directory provisioned listener-write/shared-read; listener `ReadWritePaths` no longer includes source for PostgreSQL; `PYTHONDONTWRITEBYTECODE=1` in runtime units. Added the read-only `tools/systemd_host_qualification.py` runner with service/account/systemd/process-capability/credential/socket/SELinux and pre/post reboot evidence. Local non-systemd execution correctly returns `BLOCKED_ENVIRONMENT`.

P3 validation after the fixes: focused P3/installer/PostgreSQL integration suite 35 PASS / 0 FAIL. Broad dependency-available comparison against the direct P1B/P5/P6/P8/P13 parent is parent 187 PASS / 37 FAIL / 1 SKIP versus current 193 PASS / 37 FAIL / 1 SKIP; the 37 failed node IDs are identical, so new failing nodes = 0. Repository-wide collection remains blocked by the same missing Flask/Werkzeug environment dependencies. Local live-host runner evidence is `P3_LOCAL_QUALIFICATION_2026-09-23.json` with `BLOCKED_ENVIRONMENT` because PID 1 is `supervisord`, not systemd.


## 2026-09-23 — P4 install / upgrade / resume source-truth audit

Status: `IMPLEMENTED_TESTING_DEFERRED`.

The audit did not redesign the existing installer. Fresh-vs-upgrade separation, PostgreSQL fresh checkpoint phases, transient resume secrets, config/backend/target binding, owner/runtime credential preservation and existing-upgrade staging were already implemented. Two concrete source gaps were found and fixed.

1. Fresh-install `source_fingerprint()` previously covered only seven selected files. Packaged installs now verify every immutable file recorded in `ARTIFACT_MANIFEST.json` plus the manifest bytes themselves. Development/test trees without a release manifest retain the narrow fallback only for local tooling. Runtime `db-config.json`, database files, credentials and venvs remain outside the immutable package manifest by design.
2. Existing upgrade relied on a process-local Bash `ERR` trap. A kill/reboot around the two-directory cutover could strand the stable target, and the previous rollback message could imply full recovery even after PostgreSQL schema mutation. `tools/upgrade_cutover_state.py` plus `upgrade-existing.sh --recover-interrupted` now provide a root-owned journal outside TARGET. Recovery is phase-aware: pre-database interruptions restore prior active services; interruption during DB mutation leaves services stopped and requires a controlled rerun; after DB migration, recovery completes the verified new-source cutover. If the staged source cannot be validated, P5 restore is required rather than silently starting old code against a newer schema. Fresh `--resume` semantics are unchanged.

Focused P4/installer/PostgreSQL/P3/artifact regression: **64 PASS / 0 FAIL**. Same dependency-available broad command versus the direct P3 parent: parent **191 PASS / 37 FAIL / 1 SKIP**, current **196 PASS / 37 FAIL / 1 SKIP**; all 37 failed node IDs are identical, therefore new failing nodes = **0**. The pass-count delta is the five new P4 regression tests. Live kill/reboot injection, systemd recovery, real PostgreSQL/SQLite interrupted-upgrade drills and operator acceptance remain deferred.

## 2026-09-23 — P5 backup / restore source-truth audit

Status: `IMPLEMENTED_TESTING_DEFERRED`.

The audit retained the existing backup architecture and fixed only verified gaps. PostgreSQL restore now validates the complete v1 manifest contract before any database side effect, including backend, byte count, checksum, source identity and a contiguous supported migration ledger. The manifest's historical source owner no longer controls the recovery database owner; the current deployment owner (or explicit operator override) is authoritative. Older supported ledgers are restored as `migration_required`, while newer-than-source ledgers fail closed. Backup creation refuses archive/manifest alias or overwrite and removes a dump that fails archive validation or cannot receive its manifest.

SQLite Web backup now delegates to the shared online-backup primitive, uses unique private files, verifies the copy before rotation and never returns success for a failed integrity check. The cron path now uses private creation defaults, same-second-safe names and validated positive retention. No new restore UI, HA, replication, case-management or P6 functionality was added.
Validation: focused P5 + install-entrypoint regression **24 PASS / 0 FAIL**; P5 plus packaging/release-gate contracts **33 PASS / 0 FAIL**. Same-command broad comparison against the direct P4 parent is parent **198 PASS / 37 FAIL / 1 SKIP** versus current **208 PASS / 37 FAIL / 1 SKIP**. The exact 37 failed node IDs are unchanged, so new failures = **0**. Python compileall, shell syntax, JavaScript syntax, placeholder truth and the bounded changed-Python static security scan pass.



## 2026-09-24 — P6 performance source-truth audit

Status remains `IMPLEMENTED_TESTING_DEFERRED`. Scope was P6 only; no P7+ implementation was added. The existing performance runner remained the architecture and only verified measurement-integrity gaps were fixed. Qualification target safety now uses tokenized name segments instead of substring matching; SQLite storage growth includes WAL; 24h/72h batch-latency sampling is bounded to avoid harness-induced RSS growth while exact count/min/max/mean remain exact; query/correlation measurements record and require observed benchmark rows/groups; requested cleanup failure makes evidence invalid and CLI exit non-zero; and benchmark exceptions attempt best-effort cleanup before propagation. Input and threshold values now fail closed on zero/negative or non-finite values where they would make evidence ambiguous.

Local P6 focused regression: **10 PASS / 0 FAIL**. Short SQLite smoke produced `MEASURED_NO_THRESHOLDS` plus `evidence.status=VALID`; 200/200 marker rows were visible before cleanup and cleanup removed 200 with 0 remaining. Same-command broad comparison against the direct P5 parent is parent **208 PASS / 37 FAIL / 1 SKIP** versus current **215 PASS / 37 FAIL / 1 SKIP**; the exact 37 failed node IDs are unchanged, so new failures = **0**. Production thresholds/capacity curves, queue/drop/concurrency behavior, dashboard/API/AI/archive impact, representative PostgreSQL host measurements and actual 24h/72h runs remain deferred.

## 2026-09-24 — P7 AI SOC / OpenAI source-truth audit

Status remains `IMPLEMENTED_TESTING_DEFERRED`. Scope was P7 only; no P8+ implementation was added. The existing Responses/Chat Completions architecture, encrypted external provider secret storage, redaction policy, usage audit, retry budget and opt-in live-provider harness were retained.

The audit found two provider-boundary correctness gaps and fixed only those gaps. First, a Responses refusal, Chat Completions refusal, or a completed response with no usable text could fall through to serialized raw JSON and be treated as successful analyst output. Refusals are now extracted explicitly, while completed-but-empty output fails closed with `response_empty_output` usage evidence. Second, Python urllib follows common POST redirects and can carry ordinary headers into the redirected request. External AI mode now uses a no-redirect opener so the configured endpoint must answer directly; Authorization credentials and already-approved/redacted SIEM evidence are never automatically replayed to a redirect target. Local/compatible mode keeps its prior redirect behavior for compatibility.

Source validation after the fixes: P7 AI/provider/progressive-investigation focused suite **49 PASS / 1 SKIP**; the skip is the intentionally opt-in live OpenAI call. Same-command broad comparison against the direct P6 parent is parent **215 PASS / 37 FAIL / 1 SKIP** versus current **219 PASS / 37 FAIL / 1 SKIP**; the exact 37 failed node IDs are unchanged, so new failures = **0**. Live OpenAI provider qualification remains `NOT_RUN/DEFERRED`; mocked/loopback tests do not promote P7 or the product to `TESTED`/`RELEASED`.


## 2026-09-24 — P8 ingest / parsing / detection source-truth audit

Status remains `IMPLEMENTED_TESTING_DEFERRED`. Scope was P8 only; no P9+ implementation was added. The existing CEF parser, structured field indexing, Event Storage path, correlation engine and detection architecture were retained.

The audit found three concrete ingest correctness gaps and fixed only those gaps. First, CEF detection previously accepted any `CEF:` substring anywhere in a raw/RFC message, so a normal log quoting a CEF sample could be misclassified. CEF is now recognized only when it starts the actual bare payload, a PRI-only payload, or the RFC3164/RFC5424 MSG body. Second, newline-framed TCP ingestion discarded the final complete message when a sender closed the connection without a trailing LF; EOF now flushes that final frame. Third, TCP framing could buffer indefinitely when a peer never sent a newline and did not support RFC6587 octet counting. Inbound TCP now supports RFC6587 octet-counted framing, keeps framing mode fixed per connection, caps each frame at 1 MiB, and rejects truncated/oversized/malformed frames without partially ingesting them.

P8 focused parser/framing regression after the fixes: **18 PASS / 0 FAIL**. Same-command broad comparison against the direct P7 parent is parent **219 PASS / 37 FAIL / 1 SKIP** versus current **226 PASS / 37 FAIL / 1 SKIP**; the exact 37 failed node IDs are unchanged, so new failures = **0**. Full real-network device qualification, sustained ingest/error-rate evidence and browser/UI acceptance remain deferred.


## 2026-09-28 — P9 Operational Diagnostics source-truth audit

Status remains `IMPLEMENTED_TESTING_DEFERRED`. Scope was P9 only; no P10+ implementation was added. The existing observation-only diagnostics, support-bundle, runtime heartbeat and archive/PostgreSQL status architecture were retained.

Closed only three verified source gaps:
- critical runtime unknowns (`database`, `listener`, `ingest`, `storage`) no longer permit an overall false-green `HEALTHY`; concrete WARNING/DEGRADED/FAILED state still takes precedence over unrelated UNKNOWN evidence;
- diagnostic/operator exception text now uses a shared redaction path for credential-bearing URIs, Authorization/Bearer values, API-key-like values and private-key blocks before P9 APIs/support artifacts expose it;
- the three fixed allow-listed support-bundle extension JSON slots are size-bounded, required to be valid UTF-8 JSON, recursively sanitized and only then added to the archive.

Validation: P9 focused operational/observability suite **17 PASS / 0 FAIL**; packaging/release contracts **9 PASS / 0 FAIL**. Same-command broad comparison against the direct P8 parent is parent **226 PASS / 37 FAIL / 1 SKIP** versus current **233 PASS / 37 FAIL / 1 SKIP**. The exact 37 failed node IDs are unchanged, so new failures = **0**. Python compileall, shell/JavaScript syntax, placeholder-truth gate and bounded changed-Python security scan pass. Live production incident drills and deployed support-bundle/browser acceptance remain deferred.
