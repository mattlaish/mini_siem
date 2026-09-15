# Deployment invariants

## PostgreSQL schema ownership

PostgreSQL runtime identities must never repair or initialize schema. Schema initialization and migration are explicit owner/migrator operations and must complete before listener/dashboard startup.

For this baseline the expected migration version is 26. Runtime startup is fail-closed when any migration is pending or any required runtime/archive table is missing.

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
