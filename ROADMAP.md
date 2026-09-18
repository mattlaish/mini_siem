# mini-SIEM Development Roadmap

## Canonical baseline — 2026-09-18

Current working parent artifact:

`mini_siem_openai_responses_hardening_2026-09-18.zip`

SHA-256:

`dfb2776c069b32b633f99b0770e303a8971d813aaa33af198667f795d1e8029f`

That artifact descends from `mini_siem_installer_pg_owner_fix.zip`. The current
working tree is a development baseline, not a release. No overall `TESTED` or
`RELEASED` claim is made.

## Status vocabulary

Only these roadmap states are authoritative:

- `PLANNED` — design/reference only; usable implementation does not yet exist.
- `IMPLEMENTED_TESTING_DEFERRED` — real source exists, but required qualification is incomplete.
- `TESTED` — all required gates for the stated scope actually passed.
- `RELEASED` — a tested artifact also passed formal packaging/release gates.

Documentation, phase directories, or placeholder source files never count as implementation.

## P0 — Source truth and packaging repair

Status: `TESTED`

Implemented in the 2026-09-18 working tree:

- all 19 Phase 13 pseudo-code/reference `.py` files were reclassified as Markdown design references;
- full-repository placeholder truth alignment reclassified 6 additional runtime/qualification placeholders, 6 no-op `assert True` tests, and 28 migration/release executable scaffolds;
- `tools/check_placeholder_truth.py` now blocks reintroduction of executable design placeholders and trivial tests;
- repository-wide Python syntax/compile gate is clean after reclassification;
- delivery junk/cache cleanup is enforced;
- `tools/build_source_artifact.py` now performs complete-source packaging, per-file SHA-256 manifest generation, required-file/size/shebang checks, ZIP CRC/traversal/symlink checks, extracted-artifact Python/shell/JavaScript syntax validation, and source-to-extracted byte parity;
- installer/release manifests are regenerated from current source truth during packaging.

P0 qualification evidence:

- complete-source ZIP build and clean extraction succeeded;
- ZIP CRC, traversal, symlink, required-file/size/shebang, extracted Python/shell/JavaScript syntax, and complete source-to-extracted SHA-256 parity gates passed;
- focused artifact-level P0/P1/PostgreSQL smoke suite passed 21 tests from the extracted ZIP.

This `TESTED` state applies only to the P0 source-truth/packaging-repair scope. The product and P1 PostgreSQL bootstrap remain `IMPLEMENTED_TESTING_DEFERRED`, and no `RELEASED` claim is made. Phase 13 remains `PLANNED`; moving placeholders to documentation is not feature implementation.

## P1 — PostgreSQL installer / bootstrap owner flow

### P1A — Fresh PostgreSQL bootstrap

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented:

- `configure-db.py` stores only PostgreSQL endpoint/database settings, not customer DBA credentials;
- `tools/postgres_bootstrap.py --mode fresh` accepts a temporary customer bootstrap identity, creates/checks `minisiem_owner`, creates/checks the target database, runs schema initialization/migrations only as `minisiem_owner`, provisions split runtime roles, writes component credentials, verifies runtime readiness, and persists neither customer DBA nor owner password in `db-config.json`;
- schema owner and PostgreSQL role-admin duties are separated: `minisiem_owner` remains `NOCREATEROLE`; temporary customer DBA/CREATEROLE authority creates/rotates runtime roles;
- fresh bootstrap refuses a database owned by an unexpected role and refuses to adopt a database containing application/public objects;
- `install-services.sh --bootstrap-postgres` can invoke the fresh bootstrap explicitly;
- PostgreSQL service installation now fails closed when the split runtime privilege boundary is absent;
- listener/dashboard runtime schema readiness is checked before systemd unit installation/start.

Deferred:

- live PostgreSQL fresh-install execution;
- live role/ownership/grant verification on supported PostgreSQL versions;
- live systemd startup using the generated credentials.

### P1B — Existing/legacy PostgreSQL upgrade to split boundary

Status: `PLANNED`

Current source provides a non-mutating `--mode inspect-existing` path that reports database owner, public object owners, public schema owner, migration versions, split-role presence, local credential-overlay state, and local systemd-unit presence. It explicitly does not recreate the database or transfer ownership.

Still required before this scope is implemented:

- backup-before-migration execution/evidence;
- controlled legacy owner to `minisiem_owner` ownership migration;
- idempotent interrupted owner/privilege migration recovery;
- credential rotation/re-provision workflow;
- explicit rollback/recovery procedure and tests.

## P2 — PostgreSQL privilege boundary qualification

Status: `IMPLEMENTED_TESTING_DEFERRED`

Existing implementation includes runtime `ensure_runtime_ready()`, split listener/dashboard/maintenance credentials, runtime DDL denial, migration boundary, privilege checks, guard-trigger defense in depth, archive-maintenance separation, and AI usage-audit privilege separation.

Required live gates include ownership verification, inherited privilege revocation, upgrade/downgrade, interrupted migration recovery, and PostgreSQL privilege regression.

## P3 — Linux / systemd host hardening

Status: `PLANNED`

Target: replace full-root syslog listener operation where feasible with a dedicated service identity plus narrowly scoped bind capability; add deterministic systemd sandboxing, filesystem allow-listing, capability minimization, credential isolation, restart limits, and startup dependency checks.

## P4 — Installation / upgrade reliability

Status: `IMPLEMENTED_TESTING_DEFERRED`

Some repair/reconciliation behavior exists, but the canonical three-state contract is not yet fully implemented and qualified:

- no installation -> fresh install;
- interrupted fresh install -> `install.sh --resume` only;
- operational installation -> `update.sh` only.

Resume must never become force-install. Operational upgrade/resume distinction, checkpoint verification, backup/rollback, and interrupted owner-migration recovery still require implementation/qualification.

## P5 — Backup / restore / PostgreSQL reliability

Status: `IMPLEMENTED_TESTING_DEFERRED`

Foundations exist. Live PostgreSQL backup/restore, migration-after-restore, secret exclusion, archive consistency, startup, RPO/RTO, corruption recovery, replication/failover, and reconnect/transaction integrity remain deferred.

## P6 — Performance & capacity qualification

Status: `IMPLEMENTED_TESTING_DEFERRED`

Real performance runtime tests/collectors and disposable PostgreSQL validation harnesses exist, but the former ingest/query/archive benchmark `.py` files were placeholder contracts and have been reclassified as Markdown. Production claims still require measured syslog EPS, parser/DB throughput, dashboard/correlation latency, AI/archive impact, PostgreSQL connections, memory/storage growth, and sustained 24h/72h runs. Planning estimates must remain distinct from measured evidence.

## Phase 13 — SOC workflow

All Phase 13 scopes remain `PLANNED`:

- 13.1 Alert Lifecycle
- 13.2 SOC Case Management
- 13.3 Investigation Workspace
- 13.4 Entity Context & Intelligence
- 13.5 Detection Rule Management
- 13.6 SOC Metrics Dashboard

The former pseudo-code `.py` files are now explicit Markdown references. Real DB schema, runtime logic, APIs, Web UI, audit paths, and tests are still required.

## P7 — AI SOC / OpenAI integration

Status: `IMPLEMENTED_TESTING_DEFERRED`

Current source includes OpenAI Responses API support with compatible Chat Completions fallback, external encrypted API-key storage with an off-database master, HTTPS fail-closed external egress, configurable outbound evidence redaction (`strict` default / `identifiers` / `none`), explicit Responses `failed`/`incomplete` handling, bounded HTTP/network retry with total timeout, provider/client request IDs, usage telemetry, metadata-only AI call audit, and opt-in live `gpt-5.6-luna` Responses qualification coverage. Mocked/provider regression passes; live provider qualification remains `NOT_RUN/DEFERRED` until `OPENAI_API_KEY` is supplied in an opted-in environment. Cost accounting, provider-specific model-capability catalog validation, and migration away from the current custom authenticated secretbox primitive remain later hardening work.

## P8 — Ingest / parsing / detection quality

Status: `IMPLEMENTED_TESTING_DEFERRED`

CEF/runtime parsing exists, but the former dedicated `tests/test_cef_parser.py` was only `assert True` and has been reclassified as required coverage documentation. Full network -> listener -> parser -> normalization -> DB -> search -> alert/correlation -> UI qualification remains required. Raw input remains evidence when normalization fails.

## P9 — Operational diagnostics

Status: `IMPLEMENTED_TESTING_DEFERRED`

Diagnostics remain observation-only. They must not become a migration, privilege-repair, arbitrary-shell, credential exposure, service-control, or silent archive-repair plane.

## P10 — Authentication / security review

Status: `IMPLEMENTED_TESTING_DEFERRED`

Review/qualification remains required for local auth, admin bootstrap, password change, OAuth, SAML, CSRF, session lifecycle, RBAC, API ingest keys, secret storage, and audit. The existing generated/persisted session-secret path must not be replaced with a manual-secret requirement without evidence that it fails.

## P11 — NAS-specific deployment issue

Status: `PLANNED`

The NAS Paperless PostgreSQL localhost mapping/recreation issue is infrastructure-specific. Do not encode Paperless, Docker, localhost, or fixed port assumptions into mini-SIEM.

## P12 — Full qualification

Status: `PLANNED`

Required before release: clean source gates, fully provisioned full pytest collection, database/privilege/auth/parser/dashboard/diagnostics/archive/AI/backup/performance suites, clean PostgreSQL install, existing upgrade, legacy owner migration, reboot/systemd ordering, DB outage/recovery, browser, listener/CEF ingest, AI modes, interrupted-install resume, and update rollback.

## P13 — Release engineering

Status: `PLANNED`

Release remains blocked until P12 and artifact packaging integrity gates pass. Every implementation handoff must contain the complete modifiable source baseline. Source tests alone do not make a ZIP releasable.

## Execution order

```text
P0 source truth + package cleanup
  -> P1 complete PostgreSQL bootstrap/legacy-upgrade flow
  -> P2 live PostgreSQL privilege qualification
  -> P3 Linux/systemd hardening
  -> P4 install/update/resume reliability
  -> P5 backup/restore reliability
  -> P6 measured performance qualification
  -> Phase 13.1-13.6 SOC workflow
  -> P7 AI production qualification
  -> P8 ingest/detection qualification
  -> P9/P10 operations + security qualification
  -> P12 full qualification
  -> P13 release package
```
