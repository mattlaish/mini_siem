# AI_HANDOVER.md


## PostgreSQL Migration Invariant

Runtime identities must never repair or initialize schema.

Schema initialization and migration are explicit owner/migrator operations and must complete before listener/dashboard startup.

SQLite to PostgreSQL migration must not blindly copy schema_migrations. The target version owner migration path creates the PostgreSQL schema and migration ledger first; data migration handles business records separately.

## 2026-09-13 Web Console observability handover

Use `mini_siem_postgres_migration_boundary_docs_sync_2026-09-13.zip` as the canonical parent for this slice. A previously generated `mini_siem_webconsole_observability_2026-09-13.zip` had stale lineage and must not be used as a parent.

Current invariants:
- PostgreSQL listener/dashboard runtime identities never initialize/repair schema and must use `--db-credentials` overlays.
- Migration ledger is now 30 versions; owner/migrator applies versions 22-30 before runtime startup.
- Health Web Console is observation-only for PostgreSQL security/schema and archive/maintenance state.
- Archive execution/raw-log eviction remains maintenance CLI-only.
- PostgreSQL dashboard/listener are SELECT-only on archive catalog; maintenance is the only application identity allowed to mutate archive catalog rows.
- Setup restart workflow is `sudo systemctl restart mini-siem-listener`.

Targeted validation: 15 passed. Existing Phase-6 archive suite is 5 passed / 2 failed because of pre-existing rollup/query-telemetry baseline debt; do not claim full regression green.

Final validation for this artifact: broader targeted regression 30 passed / 0 failed, static security scan 0 findings, Python/JS/shell syntax gates pass. Full pytest collection is not complete because the build environment lacks Flask/Werkzeug (3 collection errors). Live PostgreSQL/systemd/browser checks remain deferred.

## Operational Readiness & Incident Diagnostics slice (2026-09-13)

Canonical parent: `mini_siem_archive_maintenance_observability_2026-09-13.zip` (SHA-256 `a583bc6d317ff6399d98b21e32c04f3ace190c1c16f0ef061fb574f775cbc9cc`).

New implementation:
- `operational_diagnostics.py`: read-only incident aggregation + sanitized in-memory support bundle.
- Admin APIs: `GET /api/diagnostics/status`, `POST /api/diagnostics/run`, `POST /api/support/bundle`.
- Health Web Console: Incident Diagnostics + Dependencies.
- Setup Web Console: Support Bundle and five-stage syslog pipeline correlation.
- Listener runtime heartbeat includes bounded per-peer accepted/failed counters only; no payload is stored in runtime telemetry.
- Audit actions added: `DIAGNOSTIC_RUN`, `SUPPORT_BUNDLE_CREATED`, `PIPELINE_DIAGNOSTIC_RUN`.

Do not weaken these invariants in later work:
- diagnostics/support generation is not a service-control or repair plane;
- runtime roles never receive DDL/migration privilege;
- Dashboard never gets maintenance credentials;
- support bundles exclude raw event payload and secrets; service journals are not embedded;
- syslog capture remains the fixed root-owned helper with validated source IP, configured ports, bounded duration/count and no custom filter.

At implementation checkpoint: targeted suite 31 passed and static security scan found 0 issues. Consult TESTING.md and ARTIFACT_MANIFEST.json for final packaged-artifact evidence and deferred live gates.


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
## 2026-09-18 OpenAI integration hardening handover

Current AI transport/security state:
- OpenAI `api.openai.com` auto-selects the Responses API; local/other OpenAI-compatible endpoints remain on Chat Completions unless overridden.
- Responses calls explicitly set `store=false` and omit sampling parameters for broader reasoning-model compatibility.
- 429/500/502/503/504 use bounded retry/backoff; server `x-request-id` and generated client request IDs are captured.
- AI provider API keys are ciphertext in `app_config`; encryption master is outside the DB (`MINISIEM_AI_SECRET_MASTER_FILE`, systemd default `/var/lib/mini-siem/ai-secret-master.key`, mode 0600).
- `ai_usage_audit` is metadata-only and PostgreSQL runtime-protected; dashboard inserts, runtime reads, no application role updates/deletes/truncates.
- Migration ledger is 30. PostgreSQL upgrades must run owner migration then rerun `postgres_privilege_boundary.py` before services start.
- Live OpenAI testing is opt-in and must not be claimed unless `MINISIEM_OPENAI_LIVE_TEST=1` actually ran.
- If encrypted AI credentials exist but the external master is missing, startup/config access fails closed; restore the original master rather than generating a replacement.
- Local evidence: 33 targeted tests passed + 1 intentional live-provider skip; broad A/B regression has the same 32 inherited failures as the parent. Flask/live OpenAI/live PostgreSQL gates remain deferred.


## 2026-09-18 P0/P1 handover

Canonical parent used for this work: `mini_siem_openai_responses_hardening_2026-09-18.zip` (SHA-256 `dfb2776c069b32b633f99b0770e303a8971d813aaa33af198667f795d1e8029f`).

Current source invariants:

- Phase 13 is `PLANNED`. Nineteen pseudo-code/reference `.py` files were reclassified to Markdown; do not restore them as source merely to make directories look implemented.
- Repository-wide Python syntax/compile is now clean.
- PostgreSQL runtime services must have split component credentials and must call `db.ensure_runtime_ready()`; they never initialize or repair schema.
- `minisiem_owner` is the DDL/migration owner and remains `NOCREATEROLE`.
- Temporary customer DBA/role-admin authority may create/rotate PostgreSQL runtime roles during bootstrap, but its credential is never persisted in `db-config.json` or component credentials.
- Fresh PostgreSQL bootstrap refuses an existing operational/public-object database. Use `tools/postgres_bootstrap.py --mode inspect-existing` first for legacy deployments; it is read-only.
- `install-services.sh` fails closed for PostgreSQL if the split privilege boundary is not enabled and checks runtime schema readiness before systemd installation/start.
- `tools/build_source_artifact.py` is the canonical complete-source artifact packaging integrity gate for this baseline.

Validation checkpoint:

- focused P0/P1/PostgreSQL suite: 21 passed;
- repository compileall: PASS;
- static security scan: 0 findings / 29 root Python files;
- dependency-available broad comparison: current 92 passed / 41 failed / 1 skipped versus parent 82 passed / 41 failed / 1 skipped;
- full collection is incomplete because Flask/Werkzeug are unavailable here (134 collected before 3 collection errors);
- live PostgreSQL/systemd/browser/OpenAI/backup/performance gates remain deferred.

Next required slice: finish P1B existing/legacy PostgreSQL upgrade. It must require backup evidence before owner/privilege mutation, avoid automatic database recreation, implement controlled ownership migration to `minisiem_owner`, survive interruption idempotently, and define rollback/recovery plus runtime credential rotation. After P1 is complete, proceed to P2 live privilege qualification.

P0 packaging note: the bounded P0 source-truth/packaging-repair scope has passed the complete-source archive integrity gate and a 21-test smoke suite from a clean extraction. Do not interpret that as a product-level `TESTED` or `RELEASED` state; P1 and the broader qualification roadmap remain incomplete.

## Placeholder truth baseline — 2026-09-18

The repository has undergone full placeholder truth alignment. Treat `PLACEHOLDER_TRUTH_ALIGNMENT.md` and `PLACEHOLDER_TRUTH_INVENTORY.json` as canonical alongside ROADMAP/DEVELOPMENT/TESTING. Six runtime/qualification placeholder modules, six no-op tests, and 28 migration/release scaffolds were removed from executable source and remain `PLANNED`. Do not recreate them as `.py` until real observed-state implementation and non-trivial tests exist. Run `python tools/check_placeholder_truth.py` as a source gate.

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


## 2026-09-18 OpenAI egress convergence — current truth

- External mode is HTTPS fail-closed. Remote `http://` endpoints are rejected. Loopback HTTP requires explicit `MINISIEM_AI_ALLOW_INSECURE_LOOPBACK_EXTERNAL=1`.
- External evidence-redaction policy is `strict` by default, with `identifiers` and explicit `none` alternatives; redaction happens at the LLM egress boundary before payload construction.
- OpenAI Responses HTTP-200 bodies must complete; `failed` and `incomplete` are application errors and are recorded as metadata-only usage failures.
- OpenAI Chat Completions uses `max_completion_tokens`; generic/local compatible endpoints retain `max_tokens`.
- 429/5xx and transient network/timeout failures use bounded retry with a total call-time budget. Connection tests and live smoke use 128 output tokens.
- Current focused evidence: 41 passed / 1 skipped. OpenAI provider-only evidence: 19 passed / 1 skipped. The skipped test is the live provider test.
- Live `gpt-5.6-luna` Responses qualification is `NOT_RUN/DEFERRED` because `OPENAI_API_KEY` is not present in the execution environment. Never promote this to live-tested based on mocked tests.
- Overall product remains `IMPLEMENTED_TESTING_DEFERRED`; preserve the 41 inherited dependency-available regression failures as baseline debt until addressed separately.


Artifact-level verification for this slice: clean extraction, ZIP CRC/path-traversal/symlink checks, required-file and syntax gates, complete source-to-extracted SHA-256 parity, placeholder-truth gate, and the extracted AI/progressive focused suite all pass; extracted focused result is **41 passed / 1 skipped**. The skip remains the live OpenAI test because no API key is present.
