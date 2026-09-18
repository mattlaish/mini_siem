# Admin Bootstrap Preservation Required Coverage

Status: `PLANNED`

This replaces the former `tests/test_admin_bootstrap_preservation.py`, which contained only `assert True` and therefore provided no test evidence.

Required assertions:

- existing admin survives upgrade
- no admin credential overwrite
- bootstrap idempotency
- interrupted install preservation
- restore preservation
