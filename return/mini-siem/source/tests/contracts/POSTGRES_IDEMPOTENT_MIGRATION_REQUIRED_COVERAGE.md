# PostgreSQL Idempotent Migration Required Coverage

Status: `PLANNED`

This replaces the former `tests/test_postgres_idempotent_migration.py`, which contained only `assert True` and therefore provided no test evidence.

Required assertions:

- repeat owner migration
- repeat runtime-role provisioning
- no destructive ownership change
- interrupted migration resume/recovery
- migration ledger unchanged on no-op rerun
