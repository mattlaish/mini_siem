# PostgreSQL Event Storage v2

Status: `IMPLEMENTED_TESTING_DEFERRED`

This document is the canonical data-model reference for the PostgreSQL Event
Storage v2 slice.  It describes implemented source behavior.  Live PostgreSQL
migration, planner, privilege, restart, and sustained-performance qualification
remain deferred until a PostgreSQL-equipped environment is available.

## Storage planes

mini-SIEM deliberately keeps two PostgreSQL planes:

1. `logs` + `log_fields` are the raw/compatibility evidence plane.  Existing
   alert, IOC, archive, and forensic references keep their legacy log IDs.
2. `security_events` is the typed hot query projection.  It is partitioned by
   event time and carries `legacy_log_id` back to the raw evidence row.

A normal PostgreSQL ingest transaction writes the raw event, normalized dynamic
fields, and the typed projection together.  Projection failure rolls back that
transaction rather than silently creating divergent evidence/query truth.

## Typed query plane

`security_events` uses PostgreSQL-native types for the common SIEM dimensions:

- `event_time`, `ingested_at`: `TIMESTAMPTZ`;
- `src_ip`, `dst_ip`, `peer_ip`: `INET`;
- `src_port`, `dst_port`: integer;
- `severity`: small integer plus preserved text severity;
- normalized/dynamic vendor fields: `JSONB`;
- `asset_id`, `identity_id`: relational observation references;
- `message` and `raw_event`: preserved text evidence/query context.

The primary key includes event time because the parent table is range
partitioned: `(event_time, id)`.

## Partition lifecycle

`security_events` is `PARTITION BY RANGE (event_time)` with monthly child
partitions and a default safety partition.  Owner setup creates the schema and
initial partitions.  Runtime partition pre-creation is delegated to the bounded
SECURITY DEFINER function
`minisiem_ensure_security_event_partitions(start, months)`, where `months` is
restricted to 1..24.

`install-services.sh` installs `mini-siem-event-partitions.timer` for PostgreSQL
split-role deployments.  It invokes
`tools/postgres_event_partition_maintenance.py` once daily using only the
maintenance DB credential.  The timer pre-creates three months of partitions.
It never receives `minisiem_owner` credentials and never drops partitions.
Retention/deletion remains an explicit archive/evidence workflow.

Owner default table privileges are fail-closed to SELECT-only for runtime
roles, so future child partitions do not acquire broad mutation rights.  Known
mutable tables get explicit grants from `tools/postgres_privilege_boundary.py`.

## Query and index semantics

The PostgreSQL Web search path reads `security_event_logs` and uses bounded,
index-friendly semantics:

- full IP -> `INET =`;
- CIDR -> `INET <<= CIDR`;
- hostname/destination bare text -> escaped prefix lookup;
- `*text*` -> explicit contains lookup only;
- event time -> typed `TIMESTAMPTZ` range predicate;
- dynamic normalized field -> exact by default, trailing `*` for prefix,
  wrapped `*...*` for explicit contains.

The parent defines entity/time indexes for source/destination/peer IP,
asset/identity, event type, user, vendor/product, and event code, plus
hostname/destination prefix indexes.  JSONB fields have a GIN index; message
search has a text-search GIN index; event time has a BRIN index.

## Relational foundation

The slice implements minimal observational `assets` and `identities` tables and
a read-only `security_event_context` view joining typed events to those tables.
Asset primary IP observation prefers `peer_ip` (the log sender) rather than
`source_ip`, because source IP can represent an attacker or other event actor.

This is only the relational foundation.  Phase 13.4 Entity Context &
Intelligence remains `PLANNED`; there is not yet a full CMDB, AD identity graph,
vulnerability model, risk engine, or analyst entity workspace.

## Archive behavior

Archive MOVE first removes the verified hot `security_events` projection by
`legacy_log_id`, then removes normalized/raw hot rows according to the existing
archive workflow.  Archived raw evidence remains the authority.  Partition
maintenance does not silently implement evidence retention.

## Migration and qualification

The repository migration ledger is version 33.  Versions 31-33 are Event
Storage v2 boundary markers; dialect-aware owner initialization creates/repairs
the PostgreSQL v2 objects and normalized-field support before runtime readiness
is accepted.

`tools/postgres_event_storage_v2.py` is the owner-only migration/backfill and
qualification tool.  It is idempotent by `legacy_log_id`, pre-creates historical
partitions, and can inspect native types, partitioning, indexes and planner
output.  Owner credentials are prompt/in-memory inputs and are not persisted.

Required live gates still `NOT_RUN/DEFERRED` in the current build environment:

- real PostgreSQL migration/backfill of an existing deployment;
- partition creation and partition pruning evidence;
- `EXPLAIN` confirmation for representative composite-index queries;
- live split-role privilege regression, including future partitions;
- archive projection eviction against PostgreSQL;
- service restart/runtime-readiness behavior after owner migration;
- production-scale throughput and sustained retention/partition operations.
