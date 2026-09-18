# Resilience Qualification Required Coverage

Status: `PLANNED`

This replaces the former `tests/test_resilience_qualification.py`, which contained only `assert True` and therefore provided no test evidence.

Required assertions:

- database outage/recovery
- listener failure/restart
- resource pressure
- network failure
- reboot/start-order
- evidence and recovery assertions
