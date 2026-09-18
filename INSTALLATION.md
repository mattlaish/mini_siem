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

- SQLite: FTS5 when available, otherwise `LIKE`.
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
thread inside the existing listener process. `siem` remains the non-login Dashboard
service account and the listener remains `root:minisiem` when privileged syslog port
514 is used. `install-services.sh` is the service-definition/bootstrap helper for the current
development baseline. Do **not** treat re-running it as the final production
upgrade workflow: the canonical operational-install -> `update.sh` separation
remains a P4 requirement and is not yet qualified in this baseline.

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

## 3. Install both systemd services

Run as root through `sudo`:

```bash
cd /opt/mini_siem
sudo ./install-services.sh
```

The installer will, as needed:

1. create the system group `minisiem`;
2. create the non-login system user `siem`;
3. use `/var/lib/mini-siem` as the service account home;
4. prepare permissions required for SQLite/WAL and backups;
5. verify that `siem` can execute the selected Python interpreter and import Flask/Waitress;
6. install/update `mini-siem-listener.service` and `mini-siem-dashboard.service`;
7. run the listener as `root:minisiem` and dashboard as `siem:minisiem`;
8. reload systemd and start/enable the services.

The listener remains root specifically because port 514 is privileged. Do not infer from this that the dashboard should also run as root.

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
listener.py   root:minisiem
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

## 6. Upgrades

The final production update/resume state machine is still a P4 requirement. An
operational installation must ultimately use `update.sh`; `install.sh --resume`
will be reserved only for the same interrupted fresh installation. The current
source does not yet claim that complete workflow as `TESTED`.

Until P4 is completed and qualified, treat manual upgrades as controlled
development/maintenance work: back up first, preserve configuration/secrets/data,
apply PostgreSQL owner migrations before runtime startup, and do not use a fresh
bootstrap over an operational database.

For detailed SQLite migration notes and other operating details, see `README.md`.

## 7. Uninstall behavior

When the installer is used to remove the systemd services, the service account/group and application data are intentionally not assumed disposable. Review the script's uninstall output and remove `siem`, `minisiem`, databases, or backups manually only when you are certain they are no longer required.

## PostgreSQL least-privilege setup

`configure-db.py` records only the PostgreSQL host, port and database name. It
does not collect or persist a customer DBA password and does not initialize the
PostgreSQL schema.

For a **new/empty** PostgreSQL deployment:

```bash
cd /opt/mini_siem
python3 configure-db.py
MINISIEM_PG_BOOTSTRAP_USER=<customer-admin> sudo -E ./install-services.sh --bootstrap-postgres
./.venv/bin/python3 tools/postgres_privilege_check.py --db-config ./db-config.json
```

The customer administrator password is read from
`MINISIEM_PG_BOOTSTRAP_PASSWORD` or an interactive protected prompt and is never
written to runtime configuration. The bootstrap creates/uses `minisiem_owner`
for schema DDL/migrations, uses the temporary customer role-admin authority for
runtime-role creation, then writes only split component credentials.

For an **existing/legacy** PostgreSQL deployment, do not run the fresh bootstrap.
Inspect first:

```bash
MINISIEM_PG_BOOTSTRAP_USER=<customer-admin> \
  ./.venv/bin/python3 tools/postgres_bootstrap.py \
  --mode inspect-existing --db-config ./db-config.json \
  --bootstrap-user <customer-admin>
```

The inspection is non-mutating. Controlled legacy ownership/privilege migration
remains P1B work and must include backup evidence before mutation.

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

This source baseline extends the migration ledger to version 30. Versions 22-26 cover `runtime_stats` and archive catalog objects; versions 27-30 add AI usage audit storage and indexes. On PostgreSQL, apply schema changes with the owner/migrator identity before restarting runtime services. Then rerun privilege provisioning so listener/dashboard are SELECT-only on the archive catalog and maintenance retains the constrained mutation path:

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
