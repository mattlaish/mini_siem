# mini-SIEM Development Roadmap

## Canonical working baseline — 2026-09-23

Current delivery artifact:

`mini_siem_priority_hardening_alert_lifecycle_2026-09-23.zip`

Parent complete-source artifact:

`mini_siem_manual_investigate_slider_2026-09-23.zip`

Parent SHA-256:

`70ba3097d2495b04cf17dc10dcd11c9fcbf0292d1ffb8b8a6338ba96c028049b`

This 2026-09-23 delivery descends from that complete-source baseline. The current
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

This `TESTED` state applies only to the P0 source-truth/packaging-repair scope. The product and P1 PostgreSQL bootstrap remain `IMPLEMENTED_TESTING_DEFERRED`, and no `RELEASED` claim is made. At that P0 checkpoint Phase 13 remained `PLANNED`; later sections below supersede that historical status where real runtime implementation now exists.

## P1 — PostgreSQL installer / bootstrap owner flow

### P1A — Fresh PostgreSQL bootstrap

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented:

- `configure-db.py` stores only PostgreSQL endpoint/database settings, not customer DBA credentials;
- `tools/postgres_bootstrap.py --mode fresh` accepts a temporary customer bootstrap identity, creates/checks `minisiem_owner`, creates/checks the target database, runs schema initialization/migrations only as `minisiem_owner`, provisions split runtime roles, writes component credentials, verifies runtime readiness, and persists neither customer DBA nor owner password in `db-config.json`;
- schema owner and PostgreSQL role-admin duties are separated: `minisiem_owner` remains `NOCREATEROLE`; temporary customer DBA/CREATEROLE authority creates/rotates runtime roles;
- fresh bootstrap refuses a database owned by an unexpected role and refuses to adopt a database containing application/public objects;
- `fresh-install.sh` is the fail-closed operator entry point for a new install and is the only path allowed to invoke the internal PostgreSQL fresh-bootstrap mode;
- PostgreSQL service installation now fails closed when the split runtime privilege boundary is absent;
- listener/dashboard runtime schema readiness is checked before systemd unit installation/start;
- bootstrap preflight proves TCP/authenticated connectivity, verifies PostgreSQL `current_user`, and requires either superuser or both `CREATEDB` and `CREATEROLE` before any bootstrap DDL; expected failures return operator-safe diagnostics rather than raw psycopg2 tracebacks;
- interrupted fresh PostgreSQL bootstrap reuses root-only generated owner/runtime secrets and never persists the customer bootstrap password.

Deferred:

- live PostgreSQL fresh-install execution;
- live role/ownership/grant verification on supported PostgreSQL versions;
- live systemd startup using the generated credentials.

### P1B — Existing PostgreSQL upgrade

Status: `IMPLEMENTED_TESTING_DEFERRED` for **already split-role** deployments; legacy shared-role conversion remains `PLANNED`.

Implemented for the split-role path:

- `upgrade-existing.sh` is the fail-closed operator entry point and refuses a fresh/empty target;
- external `pg_dump` backup is mandatory before PostgreSQL mutation;
- owner default privileges are tightened before new owner-created Event Storage objects;
- `tools/postgres_upgrade_existing.py` performs additive owner migrations, idempotent backfill, grants-only refresh and runtime verification;
- existing listener/dashboard/maintenance passwords and credential files are preserved; no role creation/rotation occurs during upgrade;
- previous application tree is retained for source rollback.

Still `PLANNED`: controlled legacy single-owner/runtime -> `minisiem_owner` + split-role ownership migration. Live split-role PostgreSQL upgrade/rollback/reboot qualification remains deferred.

## P2 — PostgreSQL privilege boundary qualification

Status: `IMPLEMENTED_TESTING_DEFERRED`

Existing implementation includes runtime `ensure_runtime_ready()`, split listener/dashboard/maintenance credentials, runtime DDL denial, migration boundary, privilege checks, guard-trigger defense in depth, archive-maintenance separation, and AI usage-audit privilege separation.

Required live gates include ownership verification, inherited privilege revocation, upgrade/downgrade, interrupted migration recovery, and PostgreSQL privilege regression.

### P2A — PostgreSQL Event Storage v2

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented: PostgreSQL-native typed `security_events`, monthly range
partitioning, raw-evidence/typed-projection transactional ingest, composite
entity+time indexes, JSONB/message search indexes, exact IP/CIDR and prefix
query semantics, normalized dynamic-field lookup, minimal asset/identity
relational foundation, archive hot-projection eviction, bounded maintenance-role
partition pre-creation, owner-only idempotent legacy backfill/qualification, and
fail-closed future-partition default privileges.  `tools/postgres_phase4_validation.py`
uses the real v2 storage path rather than direct raw-log inserts.

Local same-suite regression comparison improved from parent 98 passed / 41
failed / 1 skipped to 109 passed / 37 failed / 1 skipped with zero new failing
node IDs.  Live PostgreSQL migration/backfill, partition pruning/EXPLAIN,
split-role privileges, archive eviction, service restart/readiness and sustained
performance remain `NOT_RUN/DEFERRED`.  The `assets`/`identities` foundation
does not by itself complete a broad Phase 13 entity graph; current IP-centered investigation/entity expansion status is documented below.

## P3 — Linux / systemd host hardening

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented in the current source:

- syslog listener runs as dedicated non-login `siem-listener`, not root; privileged port 514 binding is limited to `CAP_NET_BIND_SERVICE`;
- dashboard stays on dedicated non-login `siem`; PostgreSQL partition maintenance runs as dedicated `siem-maintenance`;
- PostgreSQL component credentials are group-separated and cross-component readability is verified before service activation;
- listener uses `NoNewPrivileges`, bind-only capability bounding, `ProtectSystem=strict`, kernel/control-group protections and restricted address families;
- dashboard and maintenance explicitly use `NoNewPrivileges` and an empty capability bounding set in addition to existing sandbox controls;
- generated service units and service-account database credential resolution are verified before the installer reports success.

Live distro/systemd/SELinux qualification remains deferred. The current SQLite layout still needs controlled write access beside `siem.db` for WAL/SHM; moving SQLite mutable state fully outside the source tree is a later hardening option, not part of this slice.

## P4 — Installation / upgrade reliability

Status: `IMPLEMENTED_TESTING_DEFERRED`

The fresh-vs-existing operator boundary is now implemented but not live-qualified:

- no installation -> `fresh-install.sh`;
- checkpointed interrupted **fresh** installation -> `fresh-install.sh --resume`;
- operational installation -> `upgrade-existing.sh`;
- `--resume` requires the same target, backend, deployment config and source fingerprint, refuses an operational install, preserves generated owner/runtime credentials, and re-runs idempotent validation without regressing a later checkpoint;
- the entry points remain mutually exclusive and fail closed; `--resume` is not a force-install or upgrade switch;
- `install-services.sh` remains a low-level reconciliation helper, not the operator upgrade interface.

`upgrade-existing.sh` stages the new source, preserves runtime state/credentials, creates backup evidence, performs owner-only PostgreSQL upgrade where applicable, retains the prior tree for rollback, then cuts over at the stable target path. Live interrupted-fresh-install, interrupted-upgrade/reboot/rollback and legacy shared-role migration remain deferred qualification items.

## P5 — Backup / restore / PostgreSQL reliability

Status: `IMPLEMENTED_TESTING_DEFERRED`

Foundations exist. Live PostgreSQL backup/restore, migration-after-restore, secret exclusion, archive consistency, startup, RPO/RTO, corruption recovery, replication/failover, and reconnect/transaction integrity remain deferred.

## P6 — Performance & capacity qualification

Status: `IMPLEMENTED_TESTING_DEFERRED`

Real performance runtime tests/collectors and disposable PostgreSQL validation harnesses exist, but the former ingest/query/archive benchmark `.py` files were placeholder contracts and have been reclassified as Markdown. Production claims still require measured syslog EPS, parser/DB throughput, dashboard/correlation latency, AI/archive impact, PostgreSQL connections, memory/storage growth, and sustained 24h/72h runs. Planning estimates must remain distinct from measured evidence.

## Phase 13 — Alert and investigation workflow

### 13.1 Alert Lifecycle

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented: durable `new -> acknowledged -> investigating -> resolved -> closed` workflow with controlled reopen, assignee, actor/timestamp/resolution-note fields, append-only workflow history, analyst API/UI controls and audit events. PostgreSQL schema repair is dialect-aware and owner-only.

### 13.2 External case-management / SOAR boundary

mini-SIEM **will not become a full case-management or SOAR product**. Existing TicketWorker integrations (Jira, ServiceNow, Zammad, osTicket, generic REST) are the handoff boundary. Raw/normalized SIEM events remain the evidence authority; external systems may carry event IDs, alert state and AI analysis. `SOC_CASE_WORKFLOW.md` is revisit/reference material only, not a core implementation commitment.

### 13.3-13.6 Revisit backlog

The current AI Analyst, `/correlate` Investigate workspace, bounded IP entity expansion, correlation playbooks and operational metrics are real implemented capabilities. A separate consolidated investigation workspace, broader non-IP entity graph, dedicated rule-management UX and additional SOC metrics remain revisit items rather than current blockers.

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

## P11 — Environment-specific deployment qualification

Status: `PLANNED`

Qualification targets may include NAS/appliance-like Linux hosts, but those systems are test environments rather than product architecture assumptions. Do not encode NAS vendors, Paperless, Docker, localhost, fixed-port, or other site-specific behavior into mini-SIEM. Reproduce environment findings as generic Linux/PostgreSQL/systemd installer requirements before promoting them into product logic.

## P11A — Product-boundary alignment: archive, ticketing, playbooks, and AI investigation

Status: `IMPLEMENTED_TESTING_DEFERRED` for the existing runtime capabilities; later scale/governance additions remain demand-driven.

Source-truth corrections for future planning:

- **Hot/cold evidence lifecycle already exists.** `archive.py` provides evidence-preserving, checksummed archive segments with configurable `hot_days`, `copy`/`move` modes, exact-payload deduplication, catalog verification, hot-copy eviction only after verification, and archive-aware search. Event Storage v2 also evicts the typed hot projection before raw hot evidence. Do not reopen "build hot/cold storage" as a greenfield roadmap item. Remaining work is measured PostgreSQL-scale qualification: prove whether hot eviction materially improves query/cache/vacuum behavior at production volumes. Object storage/Parquet or additional tiers are optional future work only when retention, cost, or measured scale justifies them.
- **Ticket integration already exists.** `workers.TicketWorker` can dispatch qualifying alerts to Jira, ServiceNow, Zammad, osTicket, or a generic REST endpoint, carries `log_ids` and `ai_analysis`, records the returned ticket reference, and retries failures. Do not list generic SIEM->ticket integration as missing. Scheduled weekly/monthly playbook findings now enter the normal alert table and inherit AI triage, Alert Lifecycle and TicketWorker handling. Conversion is idempotent and the scheduler heals a committed scheduled report whose alert conversion was interrupted. Richer vendor-specific SOAR integrations are optional external integrations, not a core case engine.
- **Do not duplicate event evidence into a second investigation log store.** Raw/normalized events remain in SIEM storage/archive. Investigation/ticket systems should reference event IDs and existing alert/AI analysis rather than clone full logs. Any future reproducibility metadata (for example playbook/profile/model/prompt identifiers) is a lower-priority debug/audit aid, not a requirement to persist duplicate evidence.
- **Playbooks are detection/investigation content, not privileged response automation.** The runtime currently contains 14 named correlation playbooks. Full SOAR-style version/approval/simulation governance is not a current product priority. If governance is added, keep it proportional: stable playbook identity and explicit enable/disable/configuration are sufficient unless playbooks later gain destructive operational actions.
- **Progressive entity expansion is deterministic and bounded, and manual scope is now visible in `/correlate`.** Alert-driven Short investigation stays on the trigger entity; Medium may follow one destination relationship after the related IP subsequently appears as a source; Long may follow two hops. The `/correlate` manual Investigate workspace exposes the same pivot rule with independent sliders for retrospective Short/Medium/Long time scope (30m/90m/5h) and 0-4 hop depth, and renders admitted entities plus relationship/proof event IDs. `peer_ip` remains evidence but is deliberately excluded from pivot discovery because it commonly identifies a collector or firewall sender. Expansion is server-controlled, not LLM-query-controlled, and is bounded by entity/event limits. The original cross-source rule remains: an admitted IP matches whether it appears as source, destination, peer, or an indexed endpoint field.

Product positioning for roadmap decisions:

`SIEM + AI-assisted investigation engine + lightweight orchestration`

Do not use a full SOAR product checklist as the default gap list for this project. Full case-management/SOAR is explicitly outside the core product boundary.

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
  -> P3 Linux/systemd live qualification
  -> P4 install/update/resume live qualification
  -> P5 backup/restore reliability
  -> P6 measured performance qualification
  -> 13.1 Alert Lifecycle live/browser qualification
  -> P7 AI production qualification
  -> P8 ingest/detection qualification
  -> P9/P10 operations + security qualification
  -> P12 full qualification
  -> P13 release package
```

## Installation entry-point split — 2026-09-19

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented:
- dedicated `fresh-install.sh` for new deployments only;
- dedicated `upgrade-existing.sh` for operational deployments only;
- direct operator access to PostgreSQL fresh bootstrap is fail-closed;
- existing split-role PostgreSQL upgrade preserves runtime credentials and uses owner-only migration/backfill + grants-only refresh;
- external PostgreSQL pre-upgrade dump and application-tree rollback retention;
- source staging/cutover at a stable target path.

Deferred live gates: real target PostgreSQL 30->33 upgrade, interrupted upgrade/resume/recovery, systemd cutover/rollback, reboot, pg_dump restore drill, and legacy shared-role -> split-role migration.

- Existing PostgreSQL upgrade migration hardening: `IMPLEMENTED_TESTING_DEFERRED` — dedicated ledger-driven 26→33-compatible path implemented; live production-like PostgreSQL migration/backfill/cutover still deferred. Fresh-install behavior unchanged.

