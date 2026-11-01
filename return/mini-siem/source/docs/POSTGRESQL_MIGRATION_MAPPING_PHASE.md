# PostgreSQL Migration Mapping Phase

## Objective

Prepare deterministic SQLite to PostgreSQL migration mappings before any
data write operation.

## Current phase

Inspection only.

No PostgreSQL changes are performed.

## Validation goals

Before enabling import:

- compare SQLite tables with PostgreSQL tables
- verify columns and types
- verify primary keys
- verify identity/authentication fields
- verify row counts
- verify relationships where applicable

## Migration safety rules

- Never overwrite existing users automatically.
- Never regenerate administrator credentials.
- Never delete target data.
- Each table import requires verification.

## Next phase

Implement controlled table import with:
- explicit transaction boundaries
- dry-run mode
- row count verification
- migration report generation
