# mini-SIEM Development Roadmap

## Canonical working baseline — 2026-09-23

Current delivery artifact:

`mini_siem_sqlite_fts5_optional_capability_2026-09-23.zip`

Parent complete-source artifact:

`mini_siem_priority_hardening_alert_lifecycle_2026-09-23.zip`

Parent SHA-256:

`2bb230f6697469a1c4ff8f225b651e48853a1b6e7fb46db79578c296c7ef64ba`

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

### P1B — Existing PostgreSQL upgrade and controlled legacy split-role conversion

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented:

- `upgrade-existing.sh` is the fail-closed operator entry point and refuses a fresh/empty target;
- external `pg_dump` backup is mandatory before PostgreSQL mutation;
- owner default privileges are tightened before new owner-created Event Storage objects;
- `tools/postgres_upgrade_existing.py` performs additive owner migrations, idempotent backfill, grants-only refresh and runtime verification;
- existing split-role listener/dashboard/maintenance passwords and credential files are preserved during normal split-role upgrade;
- previous application tree is retained for source rollback;
- `tools/postgres_legacy_split_migration.py` implements the controlled legacy shared-owner/runtime conversion after verified pre-upgrade backup evidence exists;
- the existing database owner is retained as the dedicated migration/schema owner rather than being forcibly renamed, while listener/dashboard/maintenance receive separate runtime roles;
- owner default privileges are hardened before Event Storage v2 owner DDL, then the existing ledger-driven owner upgrade/backfill runs and split grants are applied;
- candidate split credentials are verified before atomic runtime-config cutover, and the legacy owner/bootstrap password is removed from runtime configuration rather than persisted.

Live legacy conversion, split-role PostgreSQL upgrade/rollback/reboot, and interrupted-migration recovery qualification remain deferred. P1B is no longer a source implementation gap.

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

P3 hardening was tightened again after source audit. The dashboard now has a dedicated `minisiem-dashboard` credential group; `minisiem` is only the shared code/read-state group, so listener/dashboard/maintenance PostgreSQL credential files no longer conflict with the installer's cross-component readability denial. PostgreSQL deployments also remove group-write from the source tree, refuse enabled archive paths inside the application tree, and do not punch the listener sandbox write path through source code. `tools/systemd_host_qualification.py` now records live unit properties, process capabilities, account state, credential isolation, sockets, `systemd-analyze verify`, SELinux evidence, and pre/post reboot boot-ID recovery.

Live distro/systemd/SELinux/reboot qualification remains deferred. The current SQLite layout still needs controlled write access beside `siem.db` for WAL/SHM; moving SQLite mutable state fully outside the source tree is a later hardening option, not part of this slice.

## P4 — Installation / upgrade reliability

Status: `IMPLEMENTED_TESTING_DEFERRED`

The fresh-vs-existing operator boundary is implemented and source-audited, but live host qualification remains deferred:

- no installation -> `fresh-install.sh`;
- checkpointed interrupted **fresh** installation -> `fresh-install.sh --resume`;
- operational installation -> `upgrade-existing.sh`;
- `--resume` remains fresh-install-only and is never a force-install or production-upgrade switch;
- packaged fresh-install resume now verifies the complete immutable artifact manifest, not only a short installer-file subset, in addition to target/backend/config identity and monotonic phase state;
- PostgreSQL fresh resume preserves generated owner/runtime secrets in the root-only transient resume file and removes it only after `OPERATIONAL`;
- `install-services.sh` remains a low-level reconciliation helper, not the operator upgrade interface.

Existing upgrade now has a separate durable journal outside the application target and an explicit `upgrade-existing.sh --recover-interrupted` path. The journal is created before services are stopped and tracks staged source identity, target, backend, prior active services, evidence paths and cutover phase. Before database mutation, failure can safely restore the original runtime state. If interruption occurs during database mutation, services remain stopped and a controlled rerun is required so ledger/idempotent migration logic can converge. Once database migration has completed, recovery prefers completion of the verified new-source cutover; it does **not** silently start old code against a newer PostgreSQL schema. If forward recovery cannot validate the staged source, the verified P5 backup/restore path is required. This recovery mechanism is intentionally separate from fresh-install `--resume`.

Live kill/reboot injection at each upgrade phase, real systemd service recovery, PostgreSQL/SQLite data-integrity verification across interruption, and operator recovery drills remain deferred qualification items.

## P5 — Backup / restore / PostgreSQL reliability

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented source includes both the pre-upgrade dump path and the dedicated `tools/postgres_backup_restore.py` workflow. PostgreSQL backup uses custom-format `pg_dump`, validates the archive with `pg_restore -l`, records SHA-256/byte-count plus server/migration metadata, refuses archive/manifest alias or overwrite, removes an archive that fails validation, and never stores owner/bootstrap passwords in its manifest. Restore strictly validates the v1 manifest before database side effects, refuses in-place overwrite, creates a new recovery database under the **current deployment** schema owner (the source owner remains evidence only), restores with owner/ACL replay disabled, verifies the exact migration ledger, accepts older supported ledgers as `migration_required` rather than falsely requiring current-only tables, rejects backups newer than the current source understands, and removes an incomplete newly-created recovery database on failed verification when cleanup is enabled.

The SQLite online backup path now uses a shared verified primitive: unique non-overwriting names, mode `0600`, full `PRAGMA integrity_check`, SHA-256 result, and rotation only after verification. The Web API no longer reports `ok: true` when the copied database fails integrity verification. `db-maintenance.sh` now uses private creation defaults, unique same-second names and positive retention validation.

Live PostgreSQL backup/restore, migration-after-restore on representative historical backups, service startup from a restored target, RPO/RTO, corruption recovery, SQLite/ PostgreSQL crash-interruption drills, reconnect/transaction integrity, and any replication/failover behavior remain deferred. P5 source gaps identified by the 2026-09-23 audit are closed; this does not promote P5 beyond `IMPLEMENTED_TESTING_DEFERRED`.

## P6 — Performance & capacity qualification

Status: `IMPLEMENTED_TESTING_DEFERRED`

`performance_runtime_v2/qualification_runner.py` is an executable measurement harness over real parser -> batch ingest -> query -> correlation paths. It records parser/ingest EPS, batch/query/correlation latency percentiles, process RSS growth, database storage growth, and PostgreSQL connection counts where applicable; supports fixed-duration and `--sustained-hours 24` / `72` execution; and evaluates only explicitly supplied thresholds. A run without thresholds is reported as `MEASURED_NO_THRESHOLDS`, not PASS. Existing PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` validation remains complementary planner evidence.

The 2026-09-24 P6 source-truth audit closed measurement-integrity gaps without expanding scope: qualification-looking database names now require a token boundary rather than an arbitrary substring; SQLite storage growth includes the WAL file; sustained batch-latency percentiles use bounded reservoir sampling while preserving exact count/min/max/mean; the runner verifies that the inserted marker rows are visible to query and correlation paths; and requested cleanup failure makes evidence `INVALID` and the CLI non-zero. Benchmark exceptions attempt best-effort cleanup before propagation.

Production claims still require representative deployed-host measurements, dashboard/API and AI/archive impact where relevant, agreed acceptance thresholds, capacity curves, queue/drop and concurrency evidence where applicable, and actual 24h/72h sustained runs. Planning estimates and short local runner measurements must remain distinct from production qualification evidence.

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

Current source includes OpenAI Responses API support with compatible Chat Completions fallback, external encrypted API-key storage with an off-database master, HTTPS fail-closed external egress, configurable outbound evidence redaction (`strict` default / `identifiers` / `none`), explicit Responses `failed`/`incomplete` handling, refusal-aware output extraction, fail-closed completed-but-empty output handling, external-provider redirect refusal before credentials/evidence can be reused at another endpoint, bounded HTTP/network retry with total timeout, provider/client request IDs, usage telemetry, metadata-only AI call audit, and opt-in live `gpt-5.6-luna` Responses qualification coverage. Mocked/provider regression passes; live provider qualification remains `NOT_RUN/DEFERRED` until `OPENAI_API_KEY` is supplied in an opted-in environment. Cost accounting, provider-specific model-capability catalog validation, and migration away from the current custom authenticated secretbox primitive remain later hardening work.

## P8 — Ingest / parsing / detection quality

Status: `IMPLEMENTED_TESTING_DEFERRED`

CEF is now wired into the actual listener parse path rather than existing only as an unused helper. Bare CEF and RFC3164/RFC5424-wrapped CEF are recognized before generic syslog parsing; escaped header/extension content, normalized CEF severity, standard source/destination/user/action/port fields and custom extension fields are preserved in the normal event schema and `_cef` structured index. Malformed CEF falls back to raw/generic evidence rather than being dropped. `tests/test_cef_parser.py` has been restored as executable regression coverage including listener -> DB -> indexed-field -> correlation behavior.

The 2026-09-24 P8 source-truth audit closed three ingest correctness gaps without changing the detection architecture: CEF is accepted only when it begins the actual bare/PRI/RFC syslog payload rather than appearing as an arbitrary quoted substring; TCP newline framing now emits a final unterminated frame at EOF; and inbound TCP now supports bounded RFC6587 octet-counted framing with a 1 MiB per-frame ceiling and fail-closed handling for truncated/oversized frames. The TCP stream buffer is therefore no longer unbounded for peers that never send a delimiter.

Full real-network -> listener -> parser -> normalization -> DB -> search -> alert/correlation -> UI qualification, source-device variants, sustained ingest and production parser/error-rate measurements remain required. Raw input remains evidence when normalization fails.

## P9 — Operational diagnostics

Status: `IMPLEMENTED_TESTING_DEFERRED`

Diagnostics remain observation-only. They must not become a migration, privilege-repair, arbitrary-shell, credential exposure, service-control, or silent archive-repair plane.

The 2026-09-28 P9 source-truth audit closed three verified operational-diagnostics gaps without adding repair authority: critical runtime `UNKNOWN` state can no longer collapse into a false `HEALTHY` overall result; operator-facing diagnostic exception text now redacts credential-bearing connection URIs, Authorization/Bearer values, API-key patterns and private-key blocks; and allow-listed support-bundle extension JSON is now validated and sanitized through the same bounded path before the bundle can claim `contains_credentials=false`. Malformed/oversized extension JSON fails closed.

Live systemd/PostgreSQL/archive/network incident drills, browser acceptance, support-bundle inspection under the deployed dashboard identity, and external operational monitoring integration remain deferred.

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

Status: `IMPLEMENTED_TESTING_DEFERRED`

The source now contains a fail-closed final release gate (`release_engineering/release_gate.py`) and provenance generator (`release_engineering/artifact_provenance.py`) in addition to the complete-source artifact builder. The gate verifies source syntax/required files, clean-extracted artifact parity and embedded per-file manifest hashes, canonical documentation status, explicit qualification-domain evidence, provenance hashes and an explicit human release-approval record. Packaging success cannot override a non-PASS qualification domain, and missing approval cannot produce release eligibility.

Release itself remains blocked until P12/live qualification domains are PASS and the final artifact packaging integrity gate succeeds. Every implementation handoff must contain the complete modifiable source baseline. P13 implementation does not make the product `RELEASED`.

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


## SQLite FTS5 optional capability hardening — 2026-09-23

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented: SQLite core startup/ingest/search no longer requires FTS5. The
`logs_fts` virtual table, its maintenance triggers and rebuild/backfill are
gated by an actual runtime FTS5 module probe. When FTS5 is unavailable the
dashboard uses case-insensitive escaped `LIKE` search. If a database was
created previously with FTS5 and is later opened by a SQLite runtime without
FTS5, initialization removes the FTS maintenance triggers so ordinary log
writes do not depend on the unavailable module; the virtual-table metadata is
left intact for recovery if FTS5 returns.

Focused source regression: 6 PASS / 0 FAIL for FTS/no-FTS capability and
search behavior. Priority hardening plus FTS focused regression: 31 PASS / 0
FAIL. Canonical DB/Event Storage/PostgreSQL/installer/artifact-builder suite:
51 PASS / 0 FAIL. Broad dependency-available comparison: 166 PASS / 37
inherited FAIL / 1 SKIP, with 0 new failing node IDs. Flask/Werkzeug-dependent
collection remains environment-blocked for the same three modules, including
`tests/test_log_search_logic.py`; live execution using a genuinely FTS5-less
SQLite build remains deferred.

P3 source regression after this hardening: 35 focused tests PASS / 0 FAIL; broad direct-parent comparison improved from 187 PASS / 37 FAIL / 1 SKIP to 193 PASS / 37 FAIL / 1 SKIP, with the same 37 inherited failing node IDs and 0 new failures. Local host qualification is correctly `BLOCKED_ENVIRONMENT` on the non-systemd build container; representative deployed-host evidence remains the promotion gate.
