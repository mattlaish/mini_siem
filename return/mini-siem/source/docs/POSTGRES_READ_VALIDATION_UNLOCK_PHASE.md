# PostgreSQL Read Validation Unlock Phase

## Objective

Connect migration validation with a final read-only approval gate.

## Added

- PostgreSQL schema inspection boundary
- source/target row comparison
- duplicate detection report
- approval output
- migration execution unlock decision

## Safety

This phase remains read-only.

No:

- INSERT
- UPDATE
- DELETE
- schema mutation

## Unlock requirement

Migration execution requires:

- PostgreSQL connection validation
- schema compatibility result
- row comparison result
- duplicate resolution
- identity validation
- rollback readiness

## Next phase

Execute controlled PostgreSQL migration after approval.
