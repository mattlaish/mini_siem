# Controlled PostgreSQL Write Importer Phase

## Objective

Prepare the PostgreSQL write path with safety controls before enabling
real data insertion.

## Current status

This phase adds:

- explicit execute intent
- dry-run default
- import transaction design marker
- protected-table validation

No PostgreSQL INSERT operations are enabled.

## Required before enabling writes

- PostgreSQL connection handling
- table mapping verification
- transaction BEGIN/COMMIT/ROLLBACK implementation
- duplicate detection
- existing-user protection
- row count verification
- migration result report

## Protected tables

- users
- api_keys
- app_config
- audit_log

## Design rule

A successful schema initialization does not mean a successful migration.
Data migration requires verification evidence.
