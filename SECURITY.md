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
## External AI provider boundary (2026-09-18)

AI analysis remains read-only with respect to SIEM data and actions. Local OpenAI-compatible endpoints use Chat Completions; `api.openai.com` uses the Responses API automatically unless an administrator explicitly overrides the protocol. OpenAI Responses requests set `store=false`.

Provider API keys are encrypted before persistence. `app_config` stores only `ai_api_key_encrypted`; the encryption master is kept outside the database and is mode `0600` under the dashboard service account. Legacy plaintext `ai_api_key` rows are migrated to ciphertext on first successful configuration read. The API never returns the decrypted key.

`ai_usage_audit` is metadata-only and must never contain prompt/evidence text, model output, or API keys. It records provider, protocol, model, endpoint host, OpenAI/server request ID, client request ID, HTTP status, token counts, retry count, latency, and error code. In PostgreSQL privilege-boundary mode the dashboard may INSERT usage rows, runtime identities may SELECT them, and application identities may not UPDATE/DELETE/TRUNCATE them.

External AI remains an explicit data-egress choice. External mode is HTTPS-only by default and refuses insecure remote HTTP endpoints before credentials/evidence are sent. A loopback HTTP exception exists only when `MINISIEM_AI_ALLOW_INSECURE_LOOPBACK_EXTERNAL=1` is explicitly set for development. Local mode is the default.

External evidence redaction is enforced at the final LLM egress boundary, not only in the UI. `strict` is the default and masks IP/hostname/identity-like values plus removes standard raw log-message/alert-description free text; `identifiers` preserves event text while masking identifiers; `none` is an explicit operator choice to send the bounded evidence unchanged. Responses API `failed` and `incomplete` states are treated as errors, not successful analyst output. Explicit Responses/Chat refusals are parsed as provider output; a completed response with neither text nor refusal fails closed instead of exposing raw provider JSON as analysis. External-mode redirects are refused before urllib can replay Authorization headers or the approved evidence payload to a different URL. Transient HTTP and network failures are retried only within bounded retry and total-time budgets.


### AI secret restore behavior

If `app_config.ai_api_key_encrypted` exists but the external AI secret master is missing, decryption fails closed and does **not** generate replacement key material. Restore the original `/var/lib/mini-siem/ai-secret-master.key` (or the path configured by `MINISIEM_AI_SECRET_MASTER_FILE`) with mode 0600 before starting external AI use.

## PostgreSQL bootstrap credential boundary — 2026-09-18

Status: `IMPLEMENTED_TESTING_DEFERRED`

Customer PostgreSQL DBA credentials are bootstrap-only. They may be supplied via
an interactive prompt or `MINISIEM_PG_BOOTSTRAP_PASSWORD`; mini-SIEM does not
write them to `db-config.json`, component credential files, manifests, or support
bundles. The dedicated migration owner `minisiem_owner` is `NOCREATEROLE` so
schema ownership does not also become account-administration authority.

Runtime role creation/rotation is performed through a separate temporary
PostgreSQL role-admin connection, while application-object grants, default
privileges, and guard triggers are applied using the schema-owner connection.
This preserves the distinction between server/role administration, schema DDL,
and application runtime.

Fresh bootstrap is fail-closed against existing operational databases. A target
owned by an unexpected role or containing public/application objects is not
recreated, adopted, or ownership-transferred automatically. Existing deployment
inspection is read-only until the controlled legacy migration scope is
implemented and backup evidence is available.

## PostgreSQL Event Storage v2 privilege boundary — 2026-09-19

Status: `IMPLEMENTED_TESTING_DEFERRED`

`security_events` is a derived hot query plane, not a second evidence authority.
The listener may append and refresh only bounded derived columns, the dashboard
is read-only, and maintenance alone may delete verified hot projection rows.
`assets` and `identities` allow observation upserts only from the ingest role.
Runtime roles do not receive DDL.

Owner default TABLE privileges are now fail-closed to SELECT-only.  This prevents
future partitions created by the bounded SECURITY DEFINER function from
silently inheriting broad INSERT/UPDATE/DELETE/TRUNCATE rights.  Explicit
mutable grants are applied to known current tables by
`tools/postgres_privilege_boundary.py`.  The partition function is executable
only by maintenance and accepts a bounded 1..24 month horizon.  Its daily
systemd timer pre-creates partitions; it never removes evidence.

Live PostgreSQL privilege verification, including a partition created after the
boundary is applied, remains `NOT_RUN/DEFERRED` in the current environment.

## Installation/upgrade separation

`fresh-install.sh` and `upgrade-existing.sh` are intentionally mutually exclusive security boundaries. Fresh installation refuses operational state; existing upgrade refuses a fresh target and never calls fresh bootstrap. The low-level `install-services.sh --bootstrap-postgres` path requires an internal fresh-install marker.

`fresh-install.sh --resume` is bound to the same interrupted fresh installation and, for packaged source, verifies the complete immutable artifact manifest. Existing-upgrade crash/reboot recovery uses a distinct root-owned journal plus `upgrade-existing.sh --recover-interrupted`; it never reuses the fresh-install resume switch. After PostgreSQL schema migration, recovery is forward-only unless the operator explicitly invokes the verified P5 database restore path, preventing an automatic old-code/new-schema pairing from being misrepresented as safe rollback.

Existing split-role PostgreSQL upgrades preserve runtime-role passwords. The schema-owner credential is accepted only transiently from a protected environment variable or TTY prompt, is used for `pg_dump`, owner migration/backfill, and object-grant repair, and is not written to `db-config.json` or component credential files. Default privileges are tightened before Event Storage v2 creates owner-owned tables/partitions so older broad defaults cannot leak mutation rights to future objects.

## systemd service-identity hardening — 2026-09-23

Current split-service deployment does not run long-lived mini-SIEM services as
root. `siem-listener` is a non-login account with only
`CAP_NET_BIND_SERVICE` for the privileged syslog port. The dashboard uses
`siem`; PostgreSQL partition maintenance uses `siem-maintenance`. Component
PostgreSQL credential files use separate groups and the installer verifies that
one component cannot read another component's credential file.

Listener uses `NoNewPrivileges=true`, a bind-only capability bounding set,
`ProtectSystem=strict`, kernel/control-group protections and restricted address
families. Dashboard and maintenance explicitly use `NoNewPrivileges=true` and
an empty `CapabilityBoundingSet=` in addition to their existing sandboxing.
Live distro/systemd/SELinux qualification is still required before release.

## P5 recovery evidence boundary — 2026-09-23

Database backup artifacts contain sensitive operational evidence. PostgreSQL dump and manifest files are created mode 0600 and owner/bootstrap passwords are excluded. Restore treats manifest source-owner metadata as evidence only; it cannot select the target deployment owner. SQLite Web backups are created mode 0600 with unique names and are retained only after full integrity verification; the maintenance script uses `umask 077` and explicitly protects completed copies. The external AI-secret master remains separate recovery material and is not embedded in ordinary database backups.

## P8 inbound syslog framing boundary — 2026-09-24

Inbound TCP syslog is treated as hostile framing input. The listener supports newline and RFC6587 octet-counted framing, fixes framing mode for the lifetime of a connection, caps each frame at 1 MiB, and rejects malformed, truncated, or oversized octet-counted frames without partially ingesting them. CEF classification also requires `CEF:` to begin the actual syslog payload rather than merely appear inside arbitrary text; the original raw event remains preserved on parser fallback.


## P9 operational diagnostics boundary — 2026-09-28

Operational diagnostics remain read-only and admin-facing. A diagnostic state must not report `HEALTHY` when a critical database/listener/ingest/storage signal is unknown unless a concrete worse state is already reported. Driver/network exception strings are treated as untrusted diagnostic input and are redacted for credential-bearing URI userinfo, Authorization/Bearer values, API-key patterns and private-key blocks before P9 exposure. Support-bundle extension files remain a fixed allow-list; each must be bounded valid UTF-8 JSON and is recursively sanitized before inclusion. No arbitrary path, shell command, service-control, migration, privilege repair, archive repair, credential file or raw service journal is added by P9.
