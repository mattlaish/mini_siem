# Deployment invariants

## PostgreSQL schema ownership

PostgreSQL runtime identities must never repair or initialize schema. Schema initialization and migration are explicit owner/migrator operations and must complete before listener/dashboard startup.

For this baseline the expected migration version is 33. Runtime startup is fail-closed when any migration is pending or any required runtime/archive table is missing.

Upgrade order:

1. Stop or hold runtime services if schema is behind.
2. Run the owner/migrator initialization/migration path.
3. Run `tools/postgres_privilege_boundary.py` to apply runtime/maintenance grants to new objects.
4. Run `tools/postgres_privilege_check.py`.
5. Restart `mini-siem-listener` and `mini-siem-dashboard` through systemd.

Never copy a SQLite `schema_migrations` ledger blindly into PostgreSQL as ordinary business data. The target application version's owner migration path establishes the PostgreSQL migration ledger; migrate business data separately.

## Archive maintenance boundary

The Web Console only observes archive state. It never receives `db-maintenance-credentials.json`, never runs archive eviction, and never alters PostgreSQL privileges. Listener/dashboard are SELECT-only on archive catalog tables; maintenance is the constrained catalog writer and the only application identity allowed to DELETE hot raw-log copies.

## Operational diagnostics deployment notes

No new privileged Web helper is introduced by the Operational Readiness slice. The existing root-owned syslog capture helper remains the only privileged troubleshoot path. Support-bundle systemd inspection uses ordinary read-only `systemctl show` calls and degrades gracefully when systemd is unavailable or access is restricted.

Deployment-host validation should confirm:
1. the Health Diagnostics view can read the listener DB-backed heartbeat;
2. Setup > Troubleshoot shows source-specific pipeline evidence with a real sender;
3. Setup > Support bundle downloads successfully under the dashboard service identity;
4. extracted support bundles contain no credential file, secret, private key, raw event or copied service journal;
5. `audit_log` records `DIAGNOSTIC_RUN`, `SUPPORT_BUNDLE_CREATED` and `PIPELINE_DIAGNOSTIC_RUN`.
6. a missing/stale critical runtime signal is not rendered as an overall healthy diagnostic;
7. injected diagnostic error text containing URI/basic/Bearer/API-key/private-key credential forms is redacted in the API response and support bundle.


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Backup / Restore Workflow

Restore requires validated backup metadata, checksum verification, owner migration checks, privilege verification, and health validation before service startup.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED
## External AI deployment notes

Systemd deployments keep the AI provider encryption master at `/var/lib/mini-siem/ai-secret-master.key` (0600) and pass its path only to the dashboard process. OpenAI external mode uses `https://api.openai.com/v1/responses` when protocol is `auto`; local OpenAI-compatible endpoints retain `/chat/completions`. After a PostgreSQL upgrade to migration 33, rerun privilege provisioning so `ai_usage_audit` is SELECT for runtime identities, INSERT for dashboard, and non-mutable otherwise.


## PostgreSQL bootstrap boundary — 2026-09-18

Status: `IMPLEMENTED_TESTING_DEFERRED`

For a fresh PostgreSQL deployment, `tools/postgres_bootstrap.py --mode fresh`
separates three responsibilities:

1. temporary customer PostgreSQL administrator/role-admin: server validation, database/role creation, runtime-role creation;
2. `minisiem_owner`: application schema ownership and migrations only;
3. `minisiem_ingest`, `minisiem_dashboard`, `minisiem_maintenance`: runtime only.

The customer DBA credential and `minisiem_owner` password are bootstrap inputs
only and are not persisted in `db-config.json`. Component credentials are stored
in the existing split credential overlays. `install-services.sh` refuses
PostgreSQL service installation when the privilege boundary is absent and calls
`db.ensure_runtime_ready()` with listener/dashboard credentials before writing or
starting units.

Fresh bootstrap refuses to adopt an existing database with public/application
objects. Existing deployments must first use the read-only `inspect-existing`
mode; automatic database recreation or owner transfer is forbidden.

## PostgreSQL Event Storage v2 deployment — 2026-09-19

Status: `IMPLEMENTED_TESTING_DEFERRED`

Migration ledger version for this source is **33**.  Existing PostgreSQL
deployments must apply owner migration/backfill before runtime services are
restarted; runtime accounts must not repair the schema.  Use
`tools/postgres_event_storage_v2.py` with the schema owner for the explicit
migration/backfill/qualification step, then rerun the split privilege boundary
and read-only privilege check.

For split-role PostgreSQL deployments `install-services.sh` installs
`mini-siem-event-partitions.timer`.  The timer runs the bounded partition
maintenance command daily with `db-maintenance-credentials.json`.  It does not
store/use the schema-owner credential and does not drop partitions.  The
maintenance credential remains root-only; the timer's oneshot service is
sandboxed and calls only the bounded database function.

A deployment is not Event Storage v2-qualified until live PostgreSQL checks
confirm migration/backfill, native column types, partitions and pruning,
representative composite-index `EXPLAIN`, runtime role grants, hot projection
archive eviction, and post-migration service readiness.

## Deployment entry points

- New host/database: `fresh-install.sh`.
- Existing operational installation: run `upgrade-existing.sh --target /opt/mini_siem` from a separately extracted new source package.
- `install-services.sh` is an internal/low-level service reconciliation helper, not the operator upgrade interface.

The existing-upgrade script retains the previous application tree and writes upgrade evidence/DB backup outside the target tree. A durable existing-upgrade journal is also kept outside the stable target so a kill/reboot during cutover is recoverable with the explicit `--recover-interrupted` path. This is separate from fresh-install `--resume`. PostgreSQL recovery completes forward after a verified schema migration rather than silently starting old code against a newer schema; if forward recovery cannot validate the staged source, use the P5 recovery-to-new-database workflow. For PostgreSQL the upgrader supports already split-role deployments and preserves existing component DB passwords. Live production interruption/reboot qualification remains deferred.


## Controlled PostgreSQL backup / restore implementation — 2026-09-23

Use `tools/postgres_backup_restore.py` for controlled application-level PostgreSQL
backup/recovery evidence. Backup output is a custom-format archive plus SHA-256
manifest. Restore is deliberately recovery-to-new-database only: it refuses an
existing target database, restores without archive owner/ACL replay, and validates
required tables plus the migration ledger before success. This path does not
implement PostgreSQL HA/replication and does not authorize automatic production
cutover. Live restore, RPO/RTO and post-restore service qualification remain
deferred.


## P3 systemd host acceptance

The current baseline includes `tools/systemd_host_qualification.py`; use it on the deployed target to capture actual service identity, sandbox, capability, credential-isolation, socket, SELinux, and reboot evidence. PostgreSQL deployments keep application source runtime-immutable and must place enabled archive state outside the source tree. See `P3_SYSTEMD_QUALIFICATION.md`. P3 remains `IMPLEMENTED_TESTING_DEFERRED` until representative target-host evidence passes.
