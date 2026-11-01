# Actual Table Writer Implementation Phase

## Objective

Introduce table writer execution boundaries.

## Added

- explicit writer allow-list
- import ordering
- conflict decision boundary
- migration evidence structure

## Current status

Actual PostgreSQL INSERT is still disabled.

## Writer order

Low-risk data first:

1. source_profiles
2. forwarders
3. logs
4. alerts
5. iocs
6. ioc_matches
7. reports

Protected identity tables remain separate:

- users
- api_keys
- app_config
- audit_log

## Next

Implement individual PostgreSQL writers with:
- column mapping
- parameterized INSERT
- transaction handling
- duplicate policy
- row verification
