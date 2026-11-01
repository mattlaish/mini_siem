# SQLite to PostgreSQL Data Migration Plan

## Purpose

Move existing mini-SIEM application data from SQLite into PostgreSQL
without recreating identities.

## Rules

- Schema initialization is not data migration.
- Existing users must be preserved.
- Administrator accounts must not be regenerated.
- Migration must be explicit and reviewable.

## Current phase

The migration helper provides inventory/plan mode only.

Before enabling writes, validate:

- table mappings
- primary keys
- indexes
- timestamps
- authentication records
- application configuration

## Planned migration order

1. users
2. app_config
3. API/auth related records
4. logs
5. alerts
6. IOC data
7. reports/audit data

Each table migration requires verification before commit.
