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
- fresh SQLite initialization: schema migration ledger = **30**, `ai_usage_audit` present, and legacy plaintext `ai_api_key` migrated to ciphertext;
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
