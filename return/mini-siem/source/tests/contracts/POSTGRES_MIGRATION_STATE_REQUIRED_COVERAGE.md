# PostgreSQL Migration State Required Coverage

Status: `PLANNED`

This replaces the former `tests/test_postgres_migration_state.py`, which contained only `assert True` and therefore provided no test evidence.

Required assertions:

- fresh schema version
- pending migration detection
- owner-only migration application
- runtime fail-closed on pending migration
- upgrade/downgrade evidence
