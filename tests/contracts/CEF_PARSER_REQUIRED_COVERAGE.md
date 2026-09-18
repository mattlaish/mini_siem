# CEF Parser Required Coverage

Status: `PLANNED`

This replaces the former `tests/test_cef_parser.py`, which contained only `assert True` and therefore provided no test evidence.

Required assertions:

- standard CEF
- src/dst/suser/act/dpt normalization
- vendor/custom extensions
- malformed CEF raw fallback
- empty extension
- unknown vendor fields
- listener→DB→search/correlation E2E
