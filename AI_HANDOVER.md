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

## 2026-09-19 Event Storage v2 handover

Current Event Storage v2 status: `IMPLEMENTED_TESTING_DEFERRED`.

Use `EVENT_STORAGE_V2.md` as the canonical schema/boundary reference.  Keep
`logs/log_fields` as raw evidence and `security_events` as the PostgreSQL typed
hot projection; do not replace raw evidence IDs.  New PostgreSQL ingest must use
the shared storage path so raw, normalized and projection writes share a
transaction.  Full IP and CIDR queries must remain typed/index-friendly;
host/destination bare searches remain prefix and `*...*` is the explicit
contains opt-in.  Future partitions must not receive broad runtime mutation
through default privileges.  The daily partition timer uses only the
maintenance role and may pre-create partitions but never drop evidence.

The `assets`/`identities` tables and `security_event_context` are foundations,
not full broad-entity Phase 13.4 completion. Current 2026-09-23 handover sections below supersede the older blanket Phase 13 status.

Current same-suite comparison: parent 98/41/1 versus current 109/37/1
(pass/fail/skip), with zero newly failing node IDs.  Live PostgreSQL gates remain
`NOT_RUN/DEFERRED` because this environment has no usable PostgreSQL target.

Event Storage v2 artifact smoke: clean-extracted complete source passed the
27-test focused PostgreSQL/Event Storage suite plus packaging integrity gates.
Keep status `IMPLEMENTED_TESTING_DEFERRED` until the documented live PostgreSQL
gates actually run.

## 2026-09-19 installer split handover

Canonical operator workflow is now two explicit scripts: `fresh-install.sh` for new installations and `upgrade-existing.sh` for existing installations. Do not merge them back into a mode-heavy operator script. `install-services.sh` is a lower-level unit/permission helper; its PostgreSQL fresh-bootstrap option requires the internal fresh-install marker and rejects direct operator use.

Existing split-role PostgreSQL upgrade uses `tools/postgres_upgrade_existing.py`: temporary owner secret only, pre-DDL default-privilege lockdown, migrations/backfill, grants-only refresh, existing runtime credentials preserved, post-upgrade privilege verification. It does not solve legacy shared owner/runtime conversion; keep that state separate and deferred. Status remains `IMPLEMENTED_TESTING_DEFERRED` until live PostgreSQL/systemd/rollback gates pass.

Dual-entrypoint validation checkpoint: 27 focused tests pass. Identical broad-suite comparison is parent 109 passed / 37 failed / 1 skipped vs current 112 passed / 37 failed / 1 skipped, zero new failing node IDs. Full collection still stops on the same three missing Flask/Werkzeug modules. Do not promote the installer/upgrade workflow beyond `IMPLEMENTED_TESTING_DEFERRED` until live PostgreSQL/systemd/rollback/reboot gates run.

Artifact smoke checkpoint: clean-extracted dual-entrypoint complete-source package passed 27/27 focused tests and packaging integrity; handoff must use only the subsequently rebuilt/re-smoked final ZIP hash.


## 2026-09-19 handover update — legacy PostgreSQL owner upgrade fix

Current patch scope is existing upgrades only. Do not change fresh-install owner semantics. A real NAS deployment showed database `minisiem` owned by legacy role `minisiem`; runtime roles `minisiem_ingest`, `minisiem_dashboard`, `minisiem_maintenance`, and NOLOGIN group `minisiem_runtime` already existed. There was no `minisiem_owner` role. The previous upgrader guessed `minisiem_owner` and failed before migration.

`upgrade-existing.sh` now resolves an unset owner through the installed dashboard runtime credential using the installed project venv, then uses that owner for pg_dump and `postgres_upgrade_existing.py`. It also handles PostgreSQL server/client major mismatch by selecting a compatible host pg_dump or, for a localhost Docker port mapping, the matching PostgreSQL container pg_dump/pg_restore. Normal cutover and rollback run `install-services.sh` from `/opt/mini_siem` (or the configured target) to avoid wrong-CWD `import db` failures.

Fresh install remains unchanged. Overall status remains `IMPLEMENTED_TESTING_DEFERRED` until live NAS rerun succeeds.

### 2026-09-19 existing-upgrade migration correction

The NAS live run proved owner discovery/backup could proceed but failed inside generic `db.initialize()` during owner DDL. Existing PostgreSQL upgrade is now ledger-driven in `tools/postgres_upgrade_existing.py`: require a non-empty `schema_migrations`, apply only pending v1-v30 statements (the observed NAS baseline is v26), repair normalized log fields, execute Event Storage v2 PostgreSQL DDL one statement at a time with screen-visible failure context, and record v31-v33 only after successful DDL. Do not reintroduce `db.initialize()` into the existing-upgrade path. Fresh install remains unchanged. Status remains `IMPLEMENTED_TESTING_DEFERRED` until the NAS completes live 26→33 migration/backfill and post-cutover gates.


### 2026-09-19 executable-mode packaging repair

Complete-source packaging now forces declared executable entrypoints/shebang tools to ZIP Unix mode `0755` and verifies those modes in both archive metadata and a real standard-`unzip` extraction. This fixes NAS upgrades requiring manual `chmod` after extraction. The change is packaging-only and does not alter fresh-install behavior. Focused upgrade/PostgreSQL/Event Storage/build validation is 30 PASS / 0 FAIL before final artifact rebuild.


## 2026-09-20 fresh-install configuration boundary update

Canonical fresh operator workflow is now `python3 configure-db.py` followed by
`sudo ./fresh-install.sh`. Do not merge configuration selection back into the
fresh installer until this boundary has completed live qualification.
`fresh-install.sh` must consume the exact generated `db-config.json`; PostgreSQL
selection must never fall back to SQLite on parse, dependency, bootstrap, schema,
or runtime-readiness failure. Explicit runtime `--db-config` paths also fail
closed when missing/invalid. PostgreSQL systemd units are installed only after
owner migration/schema verification and split runtime credential verification.
`upgrade-existing.sh` remains a separate unchanged path.

## 2026-09-23 product-boundary / investigation handover

Delivery artifact for this alignment: `mini_siem_ai_investigation_scope_alignment_2026-09-23.zip` (complete source; SHA-256 is provided externally with the packaged artifact).

Treat these as current source invariants:

- mini-SIEM is not NAS-bound. NAS/appliance-like hosts are deployment test targets only; product logic remains generic Linux/PostgreSQL/systemd.
- `archive.py` is the existing evidence lifecycle: checksummed archive segments, copy/move, `hot_days`, archive search and verified hot-copy eviction. Do not create a second hot/cold subsystem. Add further storage tiers only after measured scale/cost/retention evidence.
- Generic REST ticketing is already implemented (`TicketWorker`) for Jira/ServiceNow/Zammad/osTicket/webhooks and includes alert `log_ids` plus `ai_analysis`. The known missing scheduled path is playbook report finding -> alert, not alert -> ticket.
- Do not duplicate full logs into an investigation evidence store. SIEM/archive remain the evidence authority; tickets/SOAR may carry references and analysis.
- The 14 correlation playbooks are detection/investigation content. Do not import full SOAR governance requirements unless playbooks later gain privileged/destructive response actions.
- Progressive AI context is server-controlled and bounded. Short uses the trigger entity only; Medium can follow one confirmed destination/related-IP -> later-source pivot; Long can follow two. Current limits are 1/6/12 entities respectively. `peer_ip` participates in evidence matching but is deliberately not used to discover new pivot entities because it often identifies the logging device/collector. The LLM never receives DB query authority.


## 2026-09-23 manual Investigate UI handover

`/correlate` now exposes **Investigate** instead of the old manual ad-hoc form.
The analyst enters an IP and controls two independent sliders: Short/Medium/Long
retrospective scope (30m/90m/5h ending now) and 0-4 confirmed entity hops.
Backend route: `POST /api/investigate/ip`; engine:
`ai_soc.gather_ip_investigation()`.

Do not reimplement pivot logic in JavaScript or the LLM. The server remains the
authority: a destination is promoted only after it later appears as
`logs.source_ip` in the selected window. Evidence for admitted entities may
match source/destination/peer/indexed fields, while `peer_ip` is not a pivot
discovery source. The old `/api/correlate` engine remains intact for playbooks
and API compatibility even though the ad-hoc correlation form is no longer the
primary manual UI.

Validation for the manual Investigate delivery: 54 PASS in the manual/AI
focused group, 40 PASS in DB/Event Storage/PostgreSQL/installer/source-builder,
2 PASS placeholder truth, compileall/shell/Correlate-JS syntax PASS. Archive
focused check remains 6 PASS / 2 inherited known failures (`hourly_log_stats`,
`_record_query_telemetry_safe`). Live Flask/browser/PostgreSQL deployment gates
remain deferred; do not promote overall status beyond
`IMPLEMENTED_TESTING_DEFERRED`.

## Current handover — 2026-09-23 priority hardening slice

Canonical development direction now includes five implemented-but-not-live-
qualified items: PostgreSQL bootstrap preflight; checkpointed fresh-install
`--resume`; non-root listener/systemd least privilege; Alert Lifecycle; and
scheduled playbook finding -> normal alert.

Important product boundary: **do not turn mini-SIEM into a full case-management
or SOAR product.** The SIEM owns collection, normalization, correlation,
playbook/investigation, AI-assisted triage, lightweight alert workflow and
outbound ticket/SOAR handoff. External ticket/SOAR platforms may be the
incident system of record. Do not resurrect the old Phase 13 case-management
references as implementation unless the product boundary is explicitly changed.

Fresh-install resume is not force-install. It must keep enforcing same target,
backend, deployment config and source fingerprint, reject operational installs,
preserve generated owner/runtime secrets, and require re-entry of the temporary
customer PostgreSQL bootstrap credential when needed. Do not persist that DBA
credential.

Alert Lifecycle is real runtime code now (`alert_workflow.py`, alert workflow
columns/table, analyst API/UI, audit events). PostgreSQL workflow schema must
stay dialect-aware and owner-only. Scheduled report alerts must stay idempotent
and remain on the normal alert path so existing AI/ticket handling is reused.

Current local evidence: focused slice 25 PASS; dependency-available broad suite
162 PASS / 37 inherited FAIL / 1 SKIP with zero new failing node IDs compared
with the parent. Three additional modules cannot collect because Flask/Werkzeug
are not installed in this offline execution environment. Live PostgreSQL,
systemd/SELinux and interrupted-install target acceptance remain deferred.
