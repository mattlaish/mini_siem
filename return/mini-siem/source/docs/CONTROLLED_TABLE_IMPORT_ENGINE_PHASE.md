# Controlled Table Import Engine

## Objective

Move from schema/mapping preparation into deterministic table-level import
planning.

## Import order

1. users
2. app_config
3. api_keys
4. source_profiles
5. forwarders
6. logs
7. alerts
8. iocs
9. ioc_matches
10. reports
11. audit_log

## Safety rules

- Dry-run is the default.
- PostgreSQL writes are disabled in this phase.
- Protected tables require explicit review.
- Existing users must not be replaced automatically.
- Administrator credentials must not be regenerated.

## Before enabling writes

Required:

- PostgreSQL target validation
- column mapping verification
- transaction handling
- duplicate detection
- row count comparison
- import result report
- rollback strategy

## Next phase

Controlled PostgreSQL write importer.
