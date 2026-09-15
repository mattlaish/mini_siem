# mini-SIEM Security Boundaries

## PostgreSQL evidence privilege boundary

Raw `logs` are security evidence and are append-only for normal application runtime identities.

### Identities

- `minisiem_runtime`: NOLOGIN group role for normal application privileges.
- `minisiem_ingest`: listener login; inherits runtime rights.
- `minisiem_dashboard`: dashboard/control-plane login; inherits runtime rights.
- `minisiem_maintenance`: maintenance login; inherits runtime rights plus controlled raw-log DELETE for archive hot-copy eviction.
- database owner/migrator: schema/DDL identity; must not be used by runtime services.

### Raw log permissions

| Identity | SELECT | INSERT | UPDATE | DELETE | TRUNCATE |
| --- | --- | --- | --- | --- | --- |
| listener | yes | yes | no | no | no |
| dashboard | yes | yes | no | no | no |
| maintenance | yes | yes | no | yes | no |

Runtime INSERT is column-scoped and excludes the `id` primary key. `schema_migrations` is runtime read-only.

Two PostgreSQL triggers provide defense in depth. `UPDATE` and `TRUNCATE` are rejected for application roles even if a table grant is added later; `DELETE` is rejected unless the caller is a member of the maintenance role.

### Secret separation

The shared `db-config.json` is non-secret once the boundary is provisioned. Component passwords live in separate ignored files:

- `db-listener-credentials.json`
- `db-dashboard-credentials.json`
- `db-maintenance-credentials.json`

The systemd installer verifies that the dashboard OS account cannot read listener or maintenance credential files.

### Schema changes

PostgreSQL listener/dashboard startup calls `db.ensure_runtime_ready()` and never performs DDL. Pending/missing migrations fail closed and must be applied using the controlled owner/migration identity.

### Archive exception

`archive.py` may delete a hot duplicate only after archive sealing/checksum/catalog verification. The DB DELETE capability exists only on the maintenance identity. This exception does not grant dashboard/ingest authority to delete security evidence.

### Residual host boundary

The current listener service still runs as root to bind port 514. Database role separation contains dashboard compromise, but host-root compromise can read root-only credentials. Future host hardening should move the listener to a dedicated unprivileged service account with narrowly scoped bind capability.

## Archive catalog maintenance boundary (2026-09-13)

Archive catalog metadata is part of the evidence lifecycle. In PostgreSQL privilege-boundary deployments, listener and dashboard identities receive SELECT-only access to `archive_segments` and `archive_occurrence_catalog`. The dedicated maintenance identity may SELECT/INSERT/UPDATE/DELETE those tables but may not TRUNCATE them. The dashboard never receives the maintenance credential and exposes no Web endpoint for archive execution or hot-log eviction.

The Health Web Console reports effective PostgreSQL privileges using the dashboard's current DB session. These values are observability, not a substitute for the deployment-host `tools/postgres_privilege_check.py` gate.

## Operational diagnostics and support-bundle boundary

The Web Console diagnostic plane is read-only. It may inspect current health, schema readiness, effective PostgreSQL runtime privileges, archive evidence, bounded listener heartbeat data and sanitized service state. It must not restart services, execute migrations, change grants, run archive/delete operations or receive owner/maintenance credentials.

Support bundles are generated from a fixed allow-list in memory. They exclude database passwords, API keys, tokens, private keys, credential files and raw log/event payloads. `journal_tail.txt` intentionally documents that journals were omitted: listener stdout can include event-message excerpts, so copying service journals into a shareable support bundle would violate data minimization. Systemd collection is limited to non-secret state properties via a fixed argv command with no shell.

Per-peer runtime telemetry is bounded and payload-free: source IP, accepted count, failed count and last-seen time only. It exists to correlate Setup > Troubleshoot packet arrival with listener/storage evidence and is not an event archive.


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Backup Security Boundary

Backup artifacts must exclude passwords, API tokens, private keys, and credential files.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED
