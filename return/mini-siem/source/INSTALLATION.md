# mini-SIEM Installation Guide

## Recommended Linux production installation

The supported Linux production deployment uses `install-services.sh` and two systemd services.

### Service identities

`install-services.sh` creates and manages these service identities automatically:

| Component | Linux identity | Purpose |
|---|---|---|
| `mini-siem-listener` | `root:minisiem` | Receives syslog on privileged TCP/UDP port 514. |
| `mini-siem-dashboard` | `siem:minisiem` | Runs the Waitress dashboard and API pollers without an interactive login account. |

The installer creates the dedicated service account with the following contract:

```text
user:          siem
primary group: minisiem
home:          /var/lib/mini-siem
shell:         /usr/sbin/nologin (or the platform-equivalent non-login shell)
account type:  system account
```

You do **not** need to create `siem` manually and you should not substitute your personal login account. The script refuses to use UID 0 for `siem`, ensures the account has a non-login shell, and sets its primary group to `minisiem`.

The shared `minisiem` group exists so the privileged listener and unprivileged dashboard can safely access the same SQLite database, including its WAL/SHM files, while keeping the dashboard process non-root.

## 1. Place the project

Recommended location:

```bash
sudo mkdir -p /opt/mini_siem
sudo cp -a <mini-siem-source>/. /opt/mini_siem/
cd /opt/mini_siem
```

Do not copy or replace another repository's `.git/` directory as part of an application upgrade.

## 2. Create the Python environment

```bash
cd /opt/mini_siem
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

`install-services.sh` prefers `/opt/mini_siem/.venv/bin/python3` when it exists.

## 2a. Choose the message-search engine

`db-config.json` now has a top-level search control:

```json
{
  "text_search": "auto"
}
```

Recommended value is `auto`:

- SQLite: FTS5 when the current SQLite runtime can actually create an FTS5 virtual table; otherwise escaped case-insensitive `LIKE`. FTS5 is optional acceleration, not a startup requirement.
- PostgreSQL: indexed native FTS first; indexed `pg_trgm` second; `ILIKE` fallback last.

Other accepted values are `fts`, `trigram`, and `like`. You can also use the
`MINISIEM_TEXT_SEARCH` environment variable as an emergency/runtime query override;
search-index provisioning still follows the persisted `db-config.json` value.
For PostgreSQL, `auto` best-effort creates the native FTS GIN index and tries
`CREATE EXTENSION IF NOT EXISTS pg_trgm` plus its GIN index. `fts` creates only
the FTS index, `trigram` creates only the trigram path, and `like` skips search
index DDL. If the database account cannot create extensions, mini-SIEM continues
running; the dashboard shows the effective fallback. A database owner can enable `pg_trgm` separately
if substring acceleration is wanted.

For SQLite, mini-SIEM probes the runtime module directly. When the probe fails, it does not create `logs_fts`, its maintenance triggers, or run FTS rebuild SQL. If an older database already contains FTS metadata but is opened by a runtime without FTS5, initialization detaches the FTS maintenance triggers so normal ingestion remains functional and search uses `LIKE`.

`python3 configure-db.py` prompts for this setting and writes it into
`db-config.json`.

## 2b. Performance defaults

No manual tuning is required to get the current safe defaults. `db-config.json` is
merged with built-in defaults at runtime, and `configure-db.py` now writes the
performance keys explicitly so they are easy to inspect and change.

For SQLite the current defaults are:

```json
"sqlite": {
  "path": "siem.db",
  "busy_timeout_ms": 5000,
  "cache_size_kib": 32768,
  "temp_store_memory": true,
  "mmap_size_mb": 128,
  "wal_autocheckpoint_pages": 1000,
  "optimize_interval_seconds": 3600
}
```

The values are bounded in code. The busy timeout applies both to SQLite's PRAGMA
and the Python driver so short listener/dashboard writer collisions wait instead
of immediately failing. `PRAGMA optimize` is rate-limited rather than executed on
every web request.

Per-event listener stdout is disabled by default:

```json
"ingest_event_logging": false,
"ingest_stats_interval_seconds": 10
```

The Phase 4 main ingest path also has a dedicated database writer:

```json
"ingest_workers": 4,
"ingest_queue_size": 10000,
"db_writer_queue_size": 20000,
"db_writer_batch_size": 100,
"db_writer_max_delay_ms": 75,
"forward_queue_size": 10000
```

The installer does not need a new OS account or service for the DB writer; it is a
thread inside the existing listener process. `siem` remains the non-login Dashboard service account. The listener runs as the
dedicated non-login `siem-listener` identity and receives only
`CAP_NET_BIND_SERVICE` for privileged syslog port 514. `install-services.sh` is now a low-level service-definition helper. Operators
use two explicit fail-closed entry points instead:

- `fresh-install.sh` — new installations only; it refuses existing runtime state.
- `upgrade-existing.sh` — existing installations only; it refuses a fresh/empty target.

The PostgreSQL fresh-bootstrap switch inside `install-services.sh` is internal
to `fresh-install.sh` and rejects direct operator use.

This prevents systemd/journald from duplicating every SIEM event. While traffic is
active, the listener emits a compact aggregate processed/received/dropped/failed,
queue-depth, and events/sec line every 10 seconds. Turn per-event output on only
for short debugging sessions.

## 2c. Archive, maintenance, and overload thresholds

mini-SIEM does **not** use age-based log deletion. Evidence archiving is deliberately
disabled by default so an upgrade cannot move data unexpectedly. Enable it only after
choosing an archive location that is backed up and available to both the listener and
dashboard processes:

```json
"archive": {
  "enabled": true,
  "directory": "/var/lib/mini-siem/archive",
  "hot_days": 30,
  "mode": "copy",
  "batch_rows": 500,
  "max_batches_per_cycle": 20,
  "run_interval_seconds": 3600,
  "verify_on_create": true
}
```

Start with `mode=copy`: sealed archive segments are created while hot rows remain.
After archive backup/monitoring is proven, `mode=move` may be used. Move mode removes
only the hot copy, and only after the sealed segment is committed, compacted,
checksummed, cataloged, re-opened, and verified. Normal Log Search still includes moved
archive evidence. Old `retention` settings from earlier builds are no longer an active
deletion policy.

The archive directory must be writable by the listener service and readable by the
dashboard service. With the standard installation, use `siem:minisiem`/`minisiem`
permissions consistently with the existing service-account model; do not make the
archive world-writable.

SQLite housekeeping is separate from archiving:

```json
"maintenance": {
  "wal_checkpoint_mb": 256,
  "incremental_vacuum_pages": 2000,
  "quick_check_interval_seconds": 86400
}
```

No live full `VACUUM` is run. The Health page shows archive counts/dedup statistics,
WAL/free-page state, query latency, and the current overload state.

For PostgreSQL deployments, also review the pool/session bounds before production and
run the disposable-database validation harness described in `TESTING.md`. Live planner
validation is not implied by installation alone.

## 3. Fresh installation

Fresh installation uses two explicit operator stages. Database selection is
completed first and deployment then consumes that exact selection. This split
prevents a failed/missing configuration from silently changing engines.

### Stage 1 — database configuration

Run from the extracted source tree:

```bash
python3 configure-db.py
```

Select SQLite or PostgreSQL and provide the requested non-secret endpoint
settings. The source artifact itself must not contain runtime `db-config.json`;
`configure-db.py` creates it locally for this deployment.

For PostgreSQL, `db-config.json` contains host/port/database only. It must not
contain the customer DBA/bootstrap password, the migration-owner password, or
runtime component passwords.

### Stage 2 — fresh deployment

```bash
sudo ./fresh-install.sh --target /opt/mini_siem
```

`fresh-install.sh` requires the previously generated `db-config.json`. It does
not delete it, re-run backend selection, or default to SQLite. Missing, malformed,
or unsupported configuration is fatal.

For PostgreSQL the installer asks for the temporary bootstrap/admin username
(default `postgres` when appropriate); the password is requested interactively
by the internal bootstrap helper. The credential is bootstrap-only and is not
persisted.

The required PostgreSQL ordering is:

1. validate the explicit PostgreSQL deployment intent;
2. prepare the project Python runtime and PostgreSQL driver;
3. collect temporary customer DBA/bootstrap credentials;
4. create/check `minisiem_owner`, `minisiem_runtime`, `minisiem_ingest`,
   `minisiem_dashboard`, and `minisiem_maintenance`;
5. create the `minisiem` database owned by `minisiem_owner`;
6. reconnect as `minisiem_owner` and run all schema creation, migrations,
   indexes, constraints, functions, and Event Storage v2 owner DDL;
7. verify schema readiness and application-object ownership;
8. generate split runtime credentials and verify the runtime privilege boundary;
9. only then install systemd units, start services, and run post-install checks.

Systemd installation is forbidden until `DATABASE_READY`, `OWNER_READY`,
`SCHEMA_MIGRATED`, `SCHEMA_VERIFIED`, and `RUNTIME_CREDENTIALS_READY` are true.
Runtime roles never create/repair schema objects. PostgreSQL failures must stop
installation; they must never fall back to SQLite.

`install-services.sh` and `tools/postgres_bootstrap.py` are internal components
of this flow, not normal operator entrypoints.

`fresh-install.sh` refuses existing systemd units, local DB state, or split-role
credential files. It will not adopt an operational database; use
`upgrade-existing.sh` for an existing deployment.

## 4. Verify the installation

```bash
getent passwd siem
id siem
getent group minisiem
sudo systemctl --no-pager -l status mini-siem-listener
sudo systemctl --no-pager -l status mini-siem-dashboard
sudo ss -lntup | grep -E ':514|:8080'
ps -eo user,group,pid,cmd | grep -E '[l]istener.py|[d]ashboard.py'
```

Expected process ownership:

```text
listener.py   siem-listener:minisiem
dashboard.py  siem:minisiem
```

Expected `siem` properties include a non-login shell such as `/usr/sbin/nologin` or `/bin/false`.

## 5. Logs and troubleshooting

```bash
sudo journalctl -u mini-siem-listener -n 100 --no-pager
sudo journalctl -u mini-siem-dashboard -n 100 --no-pager
```

If the dashboard fails with SQLite read-only/WAL errors, do not solve it by making the database world-writable. Re-run `install-services.sh` so the expected `siem:minisiem` / shared-group permissions are restored, then inspect ownership and directory permissions.

On SELinux-enforcing CentOS/RHEL systems, a project copied from a home directory can retain an inappropriate `user_home_t` label. The installer attempts a safe `restorecon` repair for `/opt`; SELinux should not be disabled as a workaround.

For PostgreSQL deployments, runtime identities must not be able to write the application source tree. The installer uses component-specific groups (`minisiem-dashboard`, `minisiem-listener`, `minisiem-maintenance`) for credential files and reserves `minisiem` as a shared code/read-state group. If archive is enabled with PostgreSQL, configure an absolute archive directory outside the source tree (recommended `/var/lib/mini-siem/archive`).

After installation or upgrade, run the read-only P3 host qualification described in `P3_SYSTEMD_QUALIFICATION.md`.

## 6. Existing-installation upgrade

Use the dedicated upgrade entry point from a **separately extracted new source tree**:

```bash
sudo -E ./upgrade-existing.sh --target /opt/mini_siem
```

The script refuses to run in place and refuses a target without operational
mini-SIEM state. It stages the new complete source, stops services, preserves
configuration/runtime credential files and local state, retains the previous
application tree as recovery evidence, then performs the stable-path cutover.
A durable root-only upgrade journal is stored outside the target tree before
services are stopped so process kill/reboot cannot erase the recovery pointer.

For an existing split-role PostgreSQL deployment it additionally:

1. requires `pg_dump` and creates an external pre-upgrade database dump;
2. obtains the schema-owner password only from `MINISIEM_PG_OWNER_PASSWORD` or a protected TTY prompt;
3. tightens the owner's default privileges **before** owner migrations create new objects;
4. applies owner-only migrations/backfill through `tools/postgres_upgrade_existing.py`;
5. refreshes object grants in preserve-existing mode;
6. never creates runtime roles and never rotates listener/dashboard/maintenance DB passwords;
7. verifies the existing component credentials and post-cutover privilege boundary.

The PostgreSQL upgrade path supports both already split-role deployments and a
controlled legacy shared-owner/runtime conversion. For the legacy path it first
requires verified pre-upgrade dump evidence, then invokes
`tools/postgres_legacy_split_migration.py`. The existing database owner is kept
as the dedicated migration/schema identity while listener/dashboard/maintenance
receive separate runtime roles; its password is removed from runtime config.
The temporary bootstrap/role-admin password is never persisted.

This workflow is implemented but remains `IMPLEMENTED_TESTING_DEFERRED` until
the live PostgreSQL/systemd/reboot/rollback gates documented in `TESTING.md` run.

### Interrupted existing-upgrade recovery

Existing-upgrade recovery is deliberately separate from fresh-install `--resume`.
If an upgrade journal exists, a normal second upgrade is refused. Run the same
source package with:

```bash
sudo -E ./upgrade-existing.sh --target /opt/mini_siem --recover-interrupted
```

Recovery is phase-aware:

- before database mutation, the staged tree may be discarded and the original
  previously-active services restarted;
- if interruption happened while database/role mutation was in progress, old
  services are **not** restarted automatically. The active journal is archived,
  services stay stopped, and the same controlled upgrade must be rerun so
  migration-ledger/idempotent logic can converge;
- after database migration is complete, recovery completes the verified new-source
  cutover rather than pairing old code with a newer PostgreSQL schema;
- if the new staged source cannot be validated, use the verified P5 PostgreSQL
  backup/restore workflow. Application-tree rollback alone is not represented as
  a full PostgreSQL schema rollback.

For packaged fresh installs, `fresh-install.sh --resume` validates the full
`ARTIFACT_MANIFEST.json` file set plus target/backend/config identity. Runtime
files and credentials are intentionally outside that immutable source manifest.

## 7. Uninstall behavior

When the installer is used to remove the systemd services, the service account/group and application data are intentionally not assumed disposable. Review the script's uninstall output and remove `siem`, `minisiem`, databases, or backups manually only when you are certain they are no longer required.

## PostgreSQL least-privilege setup

`configure-db.py` records only the PostgreSQL host, port and database name. It
does not collect or persist a customer DBA password and does not initialize the
PostgreSQL schema.

For a **new/empty** PostgreSQL deployment:

```bash
python3 configure-db.py
MINISIEM_PG_BOOTSTRAP_USER=<customer-admin> sudo -E ./fresh-install.sh --target /opt/mini_siem
/opt/mini_siem/.venv/bin/python3 /opt/mini_siem/tools/postgres_privilege_check.py --db-config /opt/mini_siem/db-config.json
```

The customer administrator password is read from
`MINISIEM_PG_BOOTSTRAP_PASSWORD` or an interactive protected prompt and is never
written to runtime configuration. The bootstrap creates/uses `minisiem_owner`
for schema DDL/migrations, uses the temporary customer role-admin authority for
runtime-role creation, then writes only split component credentials.

For an **existing split-role** PostgreSQL deployment, do not run fresh bootstrap.
Run `upgrade-existing.sh` from the newly extracted source. For an older shared-role
deployment, inspect first:

```bash
MINISIEM_PG_BOOTSTRAP_USER=<customer-admin> \
  ./.venv/bin/python3 tools/postgres_bootstrap.py \
  --mode inspect-existing --db-config ./db-config.json \
  --bootstrap-user <customer-admin>
```

The inspection is non-mutating. Controlled legacy conversion is implemented in
`upgrade-existing.sh` and `tools/postgres_legacy_split_migration.py`, and it is
allowed to mutate only after the upgrader has created and verified external
pre-upgrade PostgreSQL backup evidence. Live target qualification remains
`IMPLEMENTED_TESTING_DEFERRED`.

The provisioning tool creates separate PostgreSQL identities for listener, dashboard, and maintenance and writes:

```text
db-listener-credentials.json
db-dashboard-credentials.json
db-maintenance-credentials.json
```

`db-config.json` remains the shared non-secret database/application configuration. The installer makes dashboard credentials readable by `siem:minisiem` but keeps listener and maintenance credentials root-only.

In secure PostgreSQL mode:

- listener/dashboard can read and append raw logs;
- listener/dashboard cannot UPDATE, DELETE, or TRUNCATE raw logs;
- maintenance alone can DELETE verified hot copies during archive move;
- runtime processes cannot create/alter the schema or edit `schema_migrations`;
- the combined `siem.py` process is intentionally rejected because it collapses the listener/dashboard trust boundary.

Owner/migration credentials are intentionally not retained in the shared base config after privilege provisioning. Keep them in the operator's external secret store for controlled upgrades.

## Setup -> Troubleshoot packet capture

`install-services.sh` installs a constrained root-owned helper used by the dashboard's **Setup -> Troubleshoot** tab. The dashboard service account may sudo only that helper; the helper accepts one source IP and captures packet headers only on configured syslog ports for a short bounded window.

The host also needs `tcpdump`:

```bash
sudo dnf install -y tcpdump
sudo ./install-services.sh
```

The installer writes:

```text
/usr/local/libexec/mini-siem-syslog-capture
/etc/mini-siem/syslog-capture.json
/etc/sudoers.d/mini-siem-troubleshoot
```

Do not grant the dashboard account general `tcpdump` or unrestricted sudo access. If the Troubleshoot tab reports that the helper is missing, re-run `sudo ./install-services.sh`. If it reports that `tcpdump` is missing, install the package above and retry.


## PostgreSQL Initialization Ownership

Before starting listener/dashboard services:

1. Run owner/migrator database initialization.
2. Confirm schema_migrations is complete.
3. Start runtime services.

Runtime service accounts are intentionally unable to create or repair schema.

## Upgrade note — observability/archive schema (2026-09-13)

This source baseline extends the migration ledger to version 33. Versions 22-26 cover `runtime_stats` and archive catalog objects; versions 27-30 add AI usage audit storage and indexes; versions 31-33 establish the PostgreSQL Event Storage v2 migration boundary and typed query-plane readiness. On PostgreSQL, apply schema changes with the owner/migrator identity before restarting runtime services. Then rerun privilege provisioning so listener/dashboard are SELECT-only on the archive catalog and maintenance retains the constrained mutation path:

```bash
./.venv/bin/python3 tools/postgres_privilege_boundary.py --db-config ./db-config.json
./.venv/bin/python3 tools/postgres_privilege_check.py --db-config ./db-config.json
sudo ./install-services.sh
sudo systemctl restart mini-siem-listener mini-siem-dashboard
```

Do not grant CREATE/ALTER/migration capability to runtime identities to work around a pending migration error.
## AI provider secret at rest

`install-services.sh` provisions `/var/lib/mini-siem/ai-secret-master.key` as the dashboard service account with mode `0600` and injects it through `MINISIEM_AI_SECRET_MASTER_FILE`. Do not copy this master into `db-config.json`, `app_config`, support bundles, source archives, or backups intended to be independently portable. The database contains only the encrypted AI provider key. Preserve the master when restoring the same deployment, otherwise existing encrypted AI credentials cannot be decrypted and must be replaced.


### AI secret master backup / restore

External-provider API keys are encrypted with a deployment master outside the database. Back up `/var/lib/mini-siem/ai-secret-master.key` together with deployment secrets, but store it separately from ordinary DB backups. Preserve mode 0600. Restoring an encrypted DB without the original master fails closed; the application will not silently generate a replacement decryption key.

## Event Storage v2 existing-PostgreSQL upgrade

Status: `IMPLEMENTED_TESTING_DEFERRED`

Do not use fresh bootstrap over an operational database. Run `upgrade-existing.sh`
from a separately extracted new source tree. It creates the pre-upgrade dump,
uses a temporary owner credential, tightens default privileges before DDL, runs
`tools/postgres_upgrade_existing.py` for migration/backfill + grants-only refresh,
preserves the existing listener/dashboard/maintenance passwords, verifies the
privilege boundary, and only then reconciles/restarts systemd services. The
partition timer is installed only for PostgreSQL split-role deployments and uses
the maintenance credential, not the owner.

The current development environment has not executed this sequence against a
live PostgreSQL target; production operators must treat the live upgrade gate as
`NOT_RUN/DEFERRED` until that evidence exists.


## Existing PostgreSQL upgrades with legacy database owners

`upgrade-existing.sh` does not require an existing deployment to use the fresh-install owner name `minisiem_owner`. If `postgres_privilege_boundary.owner_role` is unset, the upgrader queries the existing database owner through the already-working dashboard runtime credential and uses that identity for the pre-upgrade dump and owner-only migration. For example, older installations owned by PostgreSQL role `minisiem` remain supported without creating or renaming an owner role.

The upgrade also verifies PostgreSQL dump compatibility. If the host `pg_dump` is older than the server and the target is a localhost Docker-published PostgreSQL instance, the upgrader may use the matching container's `pg_dump`/`pg_restore` and stream the archive to the protected host evidence directory. This behavior is upgrade-only; fresh installation behavior is unchanged.

### Existing PostgreSQL upgrade migration behavior

`upgrade-existing.sh` uses the dedicated existing-deployment migration helper. It does not use the generic fresh/bootstrap `db.initialize()` path. A populated `schema_migrations` ledger is required; the helper advances only missing legacy versions through 30, repairs normalized log-field support, applies Event Storage v2 owner DDL statement-by-statement, and records markers 31-33 only after the DDL succeeds. Any failing DDL is printed directly to the terminal with the PostgreSQL error and statement context before rollback. This behavior applies only to existing upgrades; fresh installation is unchanged.


## Fresh-install PostgreSQL preflight and interrupted resume — 2026-09-23

Fresh PostgreSQL installation now fails before any bootstrap DDL unless the
customer bootstrap identity can authenticate and PostgreSQL reports either
`rolsuper=true` or both `rolcreatedb=true` and `rolcreaterole=true`. The
preflight also verifies the authenticated `current_user` is exactly the
requested bootstrap identity. Connectivity/authentication failures identify the
target host/port and point the operator to TCP/password/`pg_hba.conf` checks.

For an interrupted **fresh** install only:

```bash
sudo ./fresh-install.sh --resume
```

Resume requires the existing `.fresh-install-state.json`, the same target,
backend, `db-config.json` SHA-256 and source fingerprint. It reuses the same
root-only generated owner/runtime secrets and revalidates completed work. It
never adopts an operational install and is not an upgrade mechanism. If the
services are operational, use `upgrade-existing.sh`.

The temporary customer PostgreSQL bootstrap password is never written to the
checkpoint or runtime config; it must be supplied again when a resumed phase
needs administrator access.


## Dedicated PostgreSQL backup / recovery workflow — 2026-09-23

`tools/postgres_backup_restore.py` provides the controlled PostgreSQL backup and
recovery path independent of an application upgrade. `backup` creates a
custom-format archive, validates it with `pg_restore -l`, writes a SHA-256
manifest with server/migration metadata, and excludes passwords. `restore`
requires that manifest, validates its checksum/byte-count/source/ledger metadata
before database side effects, refuses to overwrite an existing database, creates a
new recovery database owned by the **current deployment** schema owner, and restores
without replaying archive ownership/ACLs. The source owner recorded in the manifest
is evidence only and cannot select the target owner. Current-schema backups must
contain all runtime-required tables; an older supported ledger is restored as
`migration_required` for a controlled owner migration rather than being mislabeled
as runtime-ready. Backups from a schema newer than this source understands are
rejected. If verification fails, the newly created recovery database can be dropped
to avoid leaving a partially restored target.

Owner/bootstrap credentials are operator-supplied through protected environment or
TTY paths only and are not written to the backup manifest. Production recovery
runbooks must still qualify service cutover, RPO/RTO and representative historical
backups on real PostgreSQL hosts before release.
