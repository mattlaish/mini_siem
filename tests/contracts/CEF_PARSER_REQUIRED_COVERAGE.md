# CEF Parser Required Coverage

Status: `IMPLEMENTED_TESTING_DEFERRED`

The former trivial `tests/test_cef_parser.py` has now been replaced by real executable coverage. This document remains as the required coverage contract.

Required assertions:

- standard CEF
- src/dst/suser/act/dpt normalization
- vendor/custom extensions
- malformed CEF raw fallback
- quoted/embedded `CEF:` text must not be misclassified unless CEF starts the actual payload
- PRI-only CEF payload
- empty extension
- unknown vendor fields
- listener→DB→search/correlation E2E
- inbound TCP newline framing including final EOF frame
- RFC6587 octet-counted fragmentation/multiple-frame handling
- truncated/oversized TCP frame fail-closed behavior

Executable coverage: `tests/test_cef_parser.py` and `tests/test_syslog_tcp_framing.py`.
