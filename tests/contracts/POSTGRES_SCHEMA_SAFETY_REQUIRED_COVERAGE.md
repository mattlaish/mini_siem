# PostgreSQL Schema Safety Required Coverage

Status: `PLANNED`

This replaces the former `tests/test_postgres_schema_safety.py`, which contained only `assert True` and therefore provided no test evidence.

Required assertions:

- runtime CREATE/ALTER/DROP denial
- owner-only DDL
- unexpected ownership detection
- unexpected inherited privilege detection
- public-schema safety
