# Controlled Import Engine Phase

## Objective

Introduce a safe SQLite to PostgreSQL import workflow.

## Current implementation

The engine provides:

- dry-run workflow
- source inventory
- migration report generation
- protected identity table awareness

No PostgreSQL writes are performed.

## Protected data

- users
- api_keys
- app_config
- audit_log

## Import safety rules

- Never overwrite existing users automatically.
- Never recreate administrator accounts.
- Never delete target data.
- Never mix schema initialization with data migration.

## Future execution phase

A write-enabled importer requires:

1. PostgreSQL target validation
2. table mapping approval
3. transaction boundaries
4. row count verification
5. post-import integrity report
6. rollback strategy
