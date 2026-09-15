# AI_HANDOVER.md


## PostgreSQL Migration Invariant

Runtime identities must never repair or initialize schema.

Schema initialization and migration are explicit owner/migrator operations and must complete before listener/dashboard startup.

SQLite to PostgreSQL migration must not blindly copy schema_migrations. The target version owner migration path creates the PostgreSQL schema and migration ledger first; data migration handles business records separately.

## 2026-09-13 Web Console observability handover

Use `mini_siem_postgres_migration_boundary_docs_sync_2026-09-13.zip` as the canonical parent for this slice. A previously generated `mini_siem_webconsole_observability_2026-09-13.zip` had stale lineage and must not be used as a parent.

Current invariants:
- PostgreSQL listener/dashboard runtime identities never initialize/repair schema and must use `--db-credentials` overlays.
- Migration ledger is now 26 versions; owner/migrator applies versions 22-26 before runtime startup.
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
