# Performance Qualification Framework

Status: `IMPLEMENTED_TESTING_DEFERRED`

`performance_runtime_v2/qualification_runner.py` is the current executable measurement harness. It exercises the real parser -> batch ingest -> DB query -> correlation path and records parser/ingest EPS, batch/query/correlation latency percentiles, RSS growth, database storage growth and PostgreSQL connection counts where applicable. It supports bounded-duration runs and explicit 24h/72h sustained execution.

P6 source-truth hardening makes the evidence fail-closed rather than merely fast: qualification target names require a qualification token as a separate name segment unless `--allow-production-target` is explicitly supplied; SQLite storage footprint counts the main DB plus WAL; long-run batch latency uses a bounded reservoir so the harness does not create unbounded RSS; inserted marker rows must be visible through the query and correlation paths; and requested cleanup must complete or evidence is `INVALID` and the CLI exits non-zero. Exceptions after ingest attempt best-effort marker cleanup before being re-raised.

The runner intentionally separates performance evaluation from evidence validity. Without operator-supplied acceptance thresholds, evaluation remains `MEASURED_NO_THRESHOLDS`, never PASS. Evidence can independently be `INVALID` if the measured path did not observe the benchmark data or cleanup failed. Local/short measurements must not be reused as production sizing claims.

Production qualification still requires representative deployment hardware, agreed thresholds, capacity curves, dashboard/API and AI/archive impact where applicable, queue/drop and concurrency evidence, and actual sustained runs. The disposable PostgreSQL planner/Phase 4 validation tools remain complementary `EXPLAIN (ANALYZE, BUFFERS)` evidence rather than a substitute for production load qualification.
