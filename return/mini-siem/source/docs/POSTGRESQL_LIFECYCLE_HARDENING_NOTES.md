# PostgreSQL Lifecycle Hardening

## Scope

This package records the PostgreSQL lifecycle corrections:

- configure-db.py uses db.initialize() as the database initialization boundary.
- Bootstrap admin creation is treated as explicit provisioning only.
- Existing databases must not be modified by automatic admin creation.
- SQLite to PostgreSQL migration is separate from schema initialization.
- Existing users, roles, and identity data must be preserved during migration.

## Deployment models

### Fresh install

Database initialization:
1. Create database/schema.
2. Initialize application tables.
3. Explicitly provision bootstrap administrator.

### Migration

1. Export existing application data.
2. Import users/configuration/log data.
3. Verify application state.

Migration does not recreate administrator accounts.

## Required follow-up validation

- Fresh PostgreSQL install test.
- SQLite to PostgreSQL data migration test.
- Existing user preservation test.
- Rollback/recovery test.
