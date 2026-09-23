# mini-SIEM Testing Handover

## Completed Validation Areas

### PostgreSQL Upgrade Path

Required validation:

- existing PostgreSQL schema startup
- schema_migrations handling
- fresh database initialization
- migration skip behavior
- ALTER safety

Status:
Implemented path exists. Full regression evidence must be collected in next session.

---

## CEF Parser Validation Required

Test cases:

1. Standard CEF event
2. CEF with src/dst/suser/act/dpt
3. Vendor custom fields
4. Malformed CEF
5. Empty extension section
6. Unknown CEF vendor format

Expected behavior:

- Parsed fields displayed when possible
- Raw event always preserved on failure

---

## Operational Testing Required

- service restart after upgrade
- reboot/start-order test
- PostgreSQL unavailable behavior
- listener failure behavior
- debug evidence collection


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Phase 12.3 Backup Restore Tests

- backup manifest validation
- checksum validation
- restore preflight validation
- secret exclusion verification

Live PostgreSQL restore drill remains DEFERRED.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED

## 2026-09-18 OpenAI Responses / AI-secret hardening

Status: IMPLEMENTED_TESTING_DEFERRED

Implemented coverage:
- automatic OpenAI `/responses` selection for `api.openai.com`;
- Responses payload contract (`store=false`, `instructions`, `input`, `max_output_tokens`) and REST output parsing;
- Chat Completions compatibility for local/OpenAI-compatible servers;
- HTTP 429 retry/backoff and terminal-error accounting;
- provider `x-request-id` plus generated `X-Client-Request-Id`;
- usage token breakdown (`input`, `output`, `total`, cached, reasoning);
- external 0600 AI encryption master, plaintext-key migration, and fail-closed restore when the original master is missing;
- metadata-only usage persistence (no prompt/API-key columns);
- PostgreSQL runtime schema readiness includes `ai_usage_audit`;
- optional live OpenAI smoke test gated by `MINISIEM_OPENAI_LIVE_TEST=1` and `OPENAI_API_KEY`.

Evidence collected in the implementation environment:
- targeted AI/PostgreSQL/warning-context suite: **33 passed, 1 skipped**; the skip is the intentionally disabled live OpenAI call;
- fresh SQLite initialization: schema migration ledger = **33**, `ai_usage_audit` present, and legacy plaintext `ai_api_key` migrated to ciphertext;
- changed Python files: `py_compile` PASS;
- all shell scripts: `bash -n` PASS;
- AI page inline JavaScript: Node `--check` PASS;
- project static security scan: **0 findings across 29 scanned root Python files**;
- broad dependency-available suite: **79 passed, 32 failed, 1 skipped**. The parent artifact run of the same suite was **70 passed, 32 failed** and the exact 32 failing test node IDs are identical, so this change set introduced no new failures in that comparison. The inherited failures are existing Phase 3-6/performance/UI baseline drift and are outside this AI patch;
- whole-tree `compileall` remains non-clean in both parent and patched trees because the same 12 pre-existing design/placeholder `.py` files contain prose rather than Python. The changed Python files compile successfully.

Deferred / not claimed:
- Flask/Werkzeug-dependent tests could not be collected in this offline execution environment because Flask/Waitress/Werkzeug are not installed and package download DNS is unavailable;
- live OpenAI provider call remains NOT_RUN unless explicitly opted in with a real project API key;
- live PostgreSQL privilege verification for the new `ai_usage_audit` grants remains deferred to a PostgreSQL-equipped environment.

Do not promote this change set to TESTED or RELEASED solely from the above local evidence.

## 2026-09-18 — P0 source truth / P1 PostgreSQL bootstrap validation

Status: `IMPLEMENTED_TESTING_DEFERRED`

Local evidence:

- parent `compileall`: FAIL with 12 Phase 13 prose `.py` syntax errors;
- current repository `compileall`: PASS after all 19 Phase 13 pseudo-source files were reclassified as documentation;
- focused P0/P1/PostgreSQL unit/contract suite: 21 passed;
- all shell scripts `bash -n`: PASS (4 files);
- standalone JavaScript `node --check`: PASS (1 file, when Node available);
- static security scan: 0 findings across 29 root Python files;
- parent dependency-available comparison: 82 passed, 41 failed, 1 skipped;
- current dependency-available comparison: 92 passed, 41 failed, 1 skipped. The 41 inherited failures remain baseline debt and are not hidden by this change set;
- full pytest collection: INCOMPLETE because Flask/Werkzeug are unavailable; 134 tests collect before 3 collection errors (`test_admin_bootstrap.py`, `test_dashboard_routes.py`, `test_log_search_logic.py`).

Required P0 artifact gate before handoff:

1. regenerate `ARTIFACT_MANIFEST.json` from actual packaged files;
2. regenerate installer/release manifest truth;
3. ensure no `.git`, `__pycache__`, `.pytest_cache`, `.pyc`, `.pyo`, runtime DB, or runtime credential/master files are packaged;
4. ZIP CRC, traversal, and symlink checks;
5. extract into a clean directory;
6. validate required files, sizes, and script shebangs;
7. validate Python/shell/JavaScript syntax on extracted files;
8. compare complete source vs extracted per-file size/SHA-256;
9. run artifact-level focused smoke tests from the extracted package.

Still deferred and release-blocking:

- properly provisioned full pytest run including Flask/Werkzeug/Waitress;
- live PostgreSQL clean bootstrap and runtime privilege verification;
- existing/legacy PostgreSQL owner migration and interrupted recovery;
- systemd/reboot/start-order and PostgreSQL outage/recovery;
- browser login/dashboard/listener/CEF E2E;
- live backup/restore;
- opt-in live OpenAI;
- sustained performance/capacity qualification.

Do not promote the product or delivery artifact to `TESTED` or `RELEASED` based on the local evidence above.

### P0 artifact-level result

The P0 source-truth/packaging-repair scope is `TESTED`: complete-source ZIP build/extraction integrity passed, and the extracted artifact passed the same 21-test focused P0/P1/PostgreSQL smoke suite. Overall mini-SIEM remains `IMPLEMENTED_TESTING_DEFERRED` because full provisioned regression and live PostgreSQL/systemd/browser/backup/OpenAI/performance gates remain incomplete.

## 2026-09-18 — Full repository placeholder truth gate

Status: `TESTED` for this bounded source-truth gate only.

Reclassified and removed from executable/test evidence:
- 6 runtime/qualification placeholder `.py` modules;
- 6 tests that contained only `assert True`;
- 28 migration/release scripts that were static/planning scaffolds rather than the operations implied by their names.

The six removed no-op tests must not be counted in current or future pass totals. Required real coverage is preserved under `tests/contracts/`. The repository gate is `python tools/check_placeholder_truth.py`; it must pass together with compile/syntax/package-integrity checks. Overall product/live qualification remains deferred.

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


## 2026-09-18 OpenAI egress hardening convergence — authoritative current evidence

Status: `IMPLEMENTED_TESTING_DEFERRED`. This section supersedes older same-day AI test counts above.

Implemented/tested locally:
- HTTPS fail-closed external endpoint validation plus explicit loopback-development exception;
- external egress redaction policies (`strict` default, `identifiers`, `none`) and actual wire-payload redaction;
- Responses `completed` success contract and fail-closed handling of `failed`/`incomplete`;
- OpenAI Chat Completions `max_completion_tokens` versus generic/local `max_tokens`;
- bounded 429/5xx and transient network/timeout retries with total timeout budget;
- request IDs, `store=false`, Responses usage parsing, metadata-only audit, encrypted provider secret persistence;
- 128-token connection probe;
- configuration/UI wiring for redaction and external HTTPS validation.

Results:
- `tests/test_ai_openai_integration.py` + optional live test: **19 passed, 1 skipped**;
- AI/provider + progressive-investigation context regression: **41 passed, 1 skipped**;
- dependency-available suite with the 3 Flask/Werkzeug-uncollectable modules excluded: **98 passed, 41 failed, 1 skipped**; the same 41 failures remain inherited baseline debt;
- full repository pytest: **collection blocked** by missing `werkzeug`/`flask` in exactly `tests/test_admin_bootstrap.py`, `tests/test_dashboard_routes.py`, and `tests/test_log_search_logic.py`; this is not a pass and is not automatically an application defect;
- repository `python -m compileall`: PASS; all shell `bash -n`: PASS; AI inline JavaScript `node --check`: PASS; placeholder truth gate: PASS; static security scan: **0 findings / 29 files**.

Live qualification:
- target: OpenAI Responses API, model `gpt-5.6-luna`, fixed non-SIEM probe only;
- requires both `MINISIEM_OPENAI_LIVE_TEST=1` and `OPENAI_API_KEY`;
- current environment: `OPENAI_API_KEY` absent, therefore **NOT_RUN / DEFERRED**.

Do not claim live OpenAI qualification, product-level `TESTED`, or `RELEASED` until the live/provider and remaining release gates actually pass.


Artifact-level verification for this slice: clean extraction, ZIP CRC/path-traversal/symlink checks, required-file and syntax gates, complete source-to-extracted SHA-256 parity, placeholder-truth gate, and the extracted AI/progressive focused suite all pass; extracted focused result is **41 passed / 1 skipped**. The skip remains the live OpenAI test because no API key is present.

## 2026-09-19 — PostgreSQL Event Storage v2 evidence

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Current local evidence before final artifact packaging:
- Event Storage v2/PostgreSQL focused suite: **27 passed**;
- same dependency-available repository suite as the parent baseline, excluding
  `test_admin_bootstrap.py`, `test_dashboard_routes.py`, and
  `test_log_search_logic.py` because Flask/Werkzeug are unavailable: **109
  passed / 37 failed / 1 skipped**;
- exact parent result for that suite: **98 passed / 41 failed / 1 skipped**;
- failure-set diff: **0 new failures**; four inherited query/normalized-field
  contract failures are fixed.

Live PostgreSQL gates are **NOT_RUN/DEFERRED**: no PostgreSQL credentials/server
are available in this environment.  Required live evidence includes real
owner migration/backfill, native-type/partition inspection, partition pruning,
representative `EXPLAIN`, split-role/future-partition privileges, PostgreSQL
archive eviction, and restart/runtime readiness.  Source-level PostgreSQL mocks
or DDL-string tests do not satisfy these gates.

Current source gates: compileall PASS; 4/4 shell syntax PASS; 1/1 standalone JavaScript syntax PASS; placeholder truth PASS; static security scan: **0 findings / 30 files**; bounded secret-pattern scan: **0 findings / 325 text files**. Full pytest collection stops at the same three missing Flask/Werkzeug modules and is not counted as a pass.

Artifact-level Event Storage v2 verification: the complete-source ZIP was
clean-extracted and the 27-test Event Storage/PostgreSQL focused suite passed
from the extracted artifact.  Packaging gates also passed ZIP CRC, path
traversal, symlink rejection, junk/cache exclusion, required Event Storage v2
files, Python/shell/JavaScript syntax, placeholder truth, and complete
source-to-extracted SHA-256 parity.  This is artifact/source evidence only; the
slice remains `IMPLEMENTED_TESTING_DEFERRED` because live PostgreSQL gates were
not run.

## Fresh-install / existing-upgrade entry-point qualification

Current status: `IMPLEMENTED_TESTING_DEFERRED`.

Local gates cover shell syntax and source contracts for mutual exclusion, non-secret owner configuration, preservation of existing split-role credential files, and the internal-only fresh-bootstrap switch. Required live acceptance before promotion to `TESTED`:

- fresh SQLite install on a clean host;
- fresh PostgreSQL install on a clean database;
- existing split-role PostgreSQL migration from the prior canonical baseline to migration 33;
- verify listener/dashboard/maintenance passwords are byte-for-byte unchanged across upgrade;
- verify pre-migration default-privilege lockdown before new Event Storage partitions are created;
- `pg_dump` recovery artifact and restore drill;
- forced failure before cutover and after cutover with application-tree rollback;
- systemd restart ordering and reboot;
- runtime readiness, privilege check, partition timer, ingest/search/browser smoke after upgrade;
- interrupted migration/backfill idempotent rerun;
- legacy shared owner/runtime migration remains a separate deferred gate.

### 2026-09-19 dual-entrypoint local evidence

- fresh/upgrade/PostgreSQL/Event Storage/build focused suite: **27 passed / 0 failed**;
- same dependency-available broad suite as parent (excluding the same three Flask/Werkzeug collection blockers): **112 passed / 37 failed / 1 skipped**;
- parent Event Storage v2 artifact on the identical suite: **109 passed / 37 failed / 1 skipped**;
- failure-set diff: **0 new failing node IDs**;
- full collection remains incomplete: **150 tests collected before 3 collection errors** (`test_admin_bootstrap.py`, `test_dashboard_routes.py`, `test_log_search_logic.py`) because Flask/Werkzeug are unavailable;
- repository compileall: PASS;
- shell `bash -n`: **6/6 PASS**;
- standalone JavaScript `node --check`: **1/1 PASS**;
- placeholder-truth gate: PASS;
- bounded secret-pattern scan: **0 findings / 329 text files**;
- dynamic Flask security scan: **NOT_RUN** because Flask/Werkzeug are unavailable in this execution environment;
- live PostgreSQL fresh install, existing upgrade, pg_dump restore, systemd cutover/rollback, reboot and credential-preservation checks remain **NOT_RUN/DEFERRED**.

Artifact-level dual-entrypoint verification checkpoint: the complete-source ZIP was clean-extracted and the 27-test fresh/upgrade/PostgreSQL/Event Storage/build focused suite passed from the extracted artifact. Packaging integrity also passed CRC, traversal, symlink rejection, required files, Python/shell/JavaScript syntax, placeholder truth, and source-to-extracted SHA-256 parity. Final bytes are rebuilt after recording this evidence and must be re-smoked before handoff.


## 2026-09-19 — Existing-upgrade owner discovery / pg_dump compatibility regression

Status remains `IMPLEMENTED_TESTING_DEFERRED`; live PostgreSQL 26→33 migration on the NAS has not yet been rerun after this patch.

Local validation for this patch:

- `tests/test_install_entrypoints.py`: **6 passed / 0 failed**.
- PostgreSQL/install/Event Storage focused set: **26 passed / 0 failed**.
- Broad dependency-available comparison excluding the same three environment-blocked modules: parent **112 passed / 37 failed / 1 skipped**; current **115 passed / 37 failed / 1 skipped**; **0 new failing node IDs**.
- `bash -n upgrade-existing.sh`: PASS.
- `fresh-install.sh` SHA-256 before/after patch: unchanged.

Live gates still `NOT_RUN/DEFERRED`: actual owner discovery against a production-like target, PostgreSQL 18 container pg_dump fallback where applicable, verified custom-format archive on that target, schema migration 26→33, Event Storage v2 backfill, post-migration privilege checks, service cutover and rollback acceptance.

## 2026-09-19 — Existing PostgreSQL ledger-driven migration regression

- Existing-upgrade helper no longer calls `db.initialize(cfg)`.
- Upgrade contract tests: **7 passed / 0 failed**.
- PostgreSQL/install/Event Storage focused suite: **27 passed / 0 failed**.
- Broad dependency-available comparison excluding the same three environment-blocked modules: parent **112 passed / 37 failed / 1 skipped**; current **116 passed / 37 failed / 1 skipped**; **0 new failing node IDs**.
- `fresh-install.sh` SHA-256 remains `36b9d21836d979e8216a60c8e7a80613b764f97e4c2e74578b5a7d7315b42421` before/after this upgrade-only patch.
- Live PostgreSQL 26→33 migration/backfill, privilege refresh, service cutover and rollback acceptance on the production-like test target remain `NOT_RUN/DEFERRED`.


## 2026-09-19 — Executable-mode packaging regression

- Packaging/entrypoint contract: executable ZIP metadata is forced to `0755` for intended entrypoints even when the source copy is `0644`; ordinary files retain their regular mode.
- Standard `unzip` extraction is now an artifact gate and must preserve `0755` on every declared executable entrypoint.
- Upgrade/PostgreSQL/Event Storage/build focused suite after the packaging repair: **30 passed / 0 failed**.
- No fresh-install application logic changed; this patch is packaging metadata/integrity only.


## 2026-09-20 — Fresh-install database-intent regression gates

Status remains `IMPLEMENTED_TESTING_DEFERRED`. Local gates for this slice must
prove:

- a source artifact contains no runtime `db-config.json`;
- `configure-db.py` creates an explicit SQLite or PostgreSQL deployment intent;
- `fresh-install.sh` refuses to run without that configuration;
- `fresh-install.sh` never deletes or re-runs the configured backend selection;
- PostgreSQL selection can only enter the PostgreSQL bootstrap branch;
- `install-services.sh` has no missing/unreadable-config SQLite fallback;
- runtime `db.load_config()` fails closed when an explicitly supplied config is
  missing or malformed;
- PostgreSQL schema/ownership/runtime readiness gates complete before systemd
  unit installation;
- executable mode is preserved as 0755 after standard ZIP extraction.

Required live gates remain: clean-host SQLite install, clean-database PostgreSQL
fresh install, role/database creation, owner schema migration, split runtime
credential login, service startup/reboot, and failure injection before systemd
cutover. These remain `NOT_RUN/DEFERRED` until executed on a production-like Linux/PostgreSQL lab target.


### 2026-09-20 local validation evidence

- PostgreSQL/config/install/Event Storage/build focused regression: **39 passed / 0 failed**.
- Disposable two-stage harness: `configure-db.py` PostgreSQL selection -> exact `db-config.json` preservation -> `fresh-install.sh` -> `install-services.sh --bootstrap-postgres`: **PASS**.
- `upgrade-existing.sh`: byte-for-byte unchanged from parent, SHA-256 `f1bf5433eac3533c0936cf1ea15c768da3a8db68e1c03acdc82b70e32ed07286`.
- repository `compileall`: PASS.
- shell `bash -n`: PASS.
- placeholder truth gate: PASS.
- static security scan: **0 findings / 30 root Python files**.
- live production-like PostgreSQL role/database/schema/systemd/reboot acceptance: **NOT_RUN/DEFERRED**.

### Fresh PostgreSQL owner-initialization regression — 2026-09-21

- Static PostgreSQL schema/migration SQL containing literal `%` tokens must execute through the raw trusted DDL path.
- Parameterized runtime SQL remains on the normal psycopg2 parameterized path.
- Regression test: `tests/test_db.py::test_postgres_initialize_executes_percent_ddl_as_raw_sql`.
- Focused verification: 25 passed in `test_db.py`, `test_event_storage_v2.py`, `test_postgres_bootstrap.py`, and `test_install_entrypoints.py`.
- Live PostgreSQL schema bootstrap on a production-like Linux deployment target remains required for final qualification.

## 2026-09-23 bounded entity-expansion regression

The AI investigation context regression must preserve these contracts:

- existing same-IP cross-source evidence works when the entity appears as source, destination, peer, or indexed endpoint field;
- Short does not multi-hop;
- Medium may admit one-hop peer IPs only after they subsequently appear as a source;
- Long may admit a second hop under the same rule;
- passive destinations are not promoted merely because the trigger host contacted them;
- unrelated traffic is excluded;
- entity depth/count and evidence/candidate bounds remain application-controlled;
- the LLM never gets query/database authority.

Focused test module: `tests/test_warning_ai_context.py`.


### 2026-09-23 local regression evidence

Status remains `IMPLEMENTED_TESTING_DEFERRED`.

- AI/progressive-investigation/OpenAI integration: **45 PASS / 0 FAIL** (`test_warning_ai_context.py`, `test_investigation_profiles.py`, `test_ai_openai_integration.py`).
- DB/Event Storage/PostgreSQL/install/source-builder focused group: **40 PASS / 0 FAIL**.
- Archive/backup focused group on this delivery: **32 PASS / 2 FAIL**. The same two node IDs fail unchanged on the parent `mini_siem_fresh_postgres_percent_init_fix_baseline_2026-09-21.zip`: `test_archive_move_evicts_only_verified_hot_copy_and_preserves_evidence_rollups` (parent lacks `hourly_log_stats`) and `test_phase6_removes_age_delete_configuration_and_freezes_ioc_architecture` (parent dashboard lacks `_record_query_telemetry_safe`). They are pre-existing baseline inconsistencies, not regressions introduced by bounded entity expansion.
- Dashboard-dependent tests were not collected in this packaging environment because Flask is not installed globally; this is an environment limitation, not counted as PASS.


## 2026-09-23 manual `/correlate` Investigate regression

Status: `IMPLEMENTED_TESTING_DEFERRED`.

New focused coverage in `tests/test_manual_ip_investigate.py` verifies:

- Short/Medium/Long manual slider mapping to 30/90/300-minute retrospective
  windows;
- hop slider changes actual server-side entity-expansion depth, not only UI
  labels;
- passive destinations are not promoted;
- 0-4 hops are accepted and >4 fails closed;
- invalid IP/stage input fails closed;
- `/api/investigate/ip` route contract is present and audit-wired;
- `/correlate` contains the Investigate IP/time/hop controls and no longer
  exposes the old ad-hoc form;
- the existing correlation engine remains callable after the UI upgrade.

Focused local regression in the packaging environment:

- manual Investigate + progressive AI context/profile/OpenAI integration:
  **54 PASS / 0 FAIL**;
- `ai_soc.py`, `dashboard.py`, `correlations.py`, and
  `investigation_profiles.py` compile: **PASS**;
- `/correlate` inline JavaScript `node --check`: **PASS**.

Flask-dependent live route/browser pytest remains environment-limited because
Flask is not installed in this packaging container and network package install
is unavailable. This is not counted as PASS. Production-like browser,
PostgreSQL and sustained scale qualification remain `NOT_RUN/DEFERRED`.

### 2026-09-23 final local evidence for manual Investigate delivery

- Manual Investigate + progressive AI context/profile/OpenAI focused group:
  **54 PASS / 0 FAIL**.
- DB/Event Storage/PostgreSQL/installer/source-builder focused group:
  **40 PASS / 0 FAIL**.
- Archive/backup focused check executed here: **6 PASS / 2 FAIL**. The two
  failures are the same inherited baseline nodes already documented above:
  missing `hourly_log_stats` and missing `_record_query_telemetry_safe`; this
  delivery does not modify either subsystem and does not count them as passed.
- Placeholder truth gate: **2 PASS / 0 FAIL**.
- Repository `compileall`: PASS.
- All 6 shell scripts `bash -n`: PASS.
- `/correlate` inline JavaScript `node --check`: PASS.
- Flask-dependent live route/browser tests remain `NOT_RUN/DEFERRED` in this
  packaging environment because Flask is unavailable and package installation
  has no network access.
- Static security scan after manual Investigate SQL assembly review: **0 findings / 30 root Python files**.

## 2026-09-23 Priority hardening + Alert Lifecycle validation

Status: `IMPLEMENTED_TESTING_DEFERRED`.

Focused source tests:

```text
tests/test_postgres_bootstrap_preflight.py
tests/test_fresh_install_resume.py
tests/test_systemd_least_privilege.py
tests/test_alert_lifecycle.py
tests/test_scheduled_playbook_alerts.py

25 PASS / 0 FAIL
```

Coverage includes bootstrap identity/privilege denial before DDL, clean
connect/auth diagnostics, admin-connection cleanup, stable root-only resume
secrets, same-source/config resume validation, phase-regression protection with
idempotent earlier-phase revalidation, non-root listener bind capability,
capability drops for dashboard/maintenance, Alert Lifecycle state machine and
schema, PostgreSQL dialect-aware workflow-event ID DDL, scheduled finding alert
creation, manual-report non-alert behavior, idempotency, and healing after a
report-commit/alert-emission interruption.

Broad same-environment comparison (excluding the same three modules that cannot
collect without Flask/Werkzeug):

```text
parent:  137 PASS / 37 FAIL / 1 SKIP
current: 162 PASS / 37 FAIL / 1 SKIP
new failing node IDs: 0
```

Full collection remains environment-blocked at
`test_admin_bootstrap.py`, `test_dashboard_routes.py`, and
`test_log_search_logic.py` because Flask/Werkzeug are not installed. An attempt
to install `requirements.txt`/`requirements-dev.txt` failed because the runner
has no DNS/network access; this is an environment limitation, not a product
PASS or FAIL.

Still `NOT_RUN/DEFERRED`: live PostgreSQL bootstrap/preflight, interruption at
each fresh-install phase and resume on a real host, generated systemd unit
execution/SELinux labels/capabilities, browser exercise of Alert Lifecycle, and
scheduled report -> alert -> external ticket end-to-end delivery.
