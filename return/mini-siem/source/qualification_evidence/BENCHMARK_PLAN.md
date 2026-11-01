# Benchmark Qualification Plan

Status: `IMPLEMENTED_TESTING_DEFERRED`

Implemented source-backed core measurement path:
- parser events/sec;
- batch database ingest events/sec and commit latency;
- query p50/p95/p99 latency plus observed result counts;
- correlation p50/p95/p99 latency plus observed group counts;
- process RSS growth;
- SQLite main+WAL or PostgreSQL database storage growth;
- PostgreSQL connection count where available;
- bounded 24h/72h ingest execution support;
- explicit threshold evaluation with `MEASURED_NO_THRESHOLDS` when no thresholds are supplied;
- marker-path integrity and cleanup validity checks.

Production qualification still requires real-environment evidence for:
- queue pressure/drop behavior and sustained error behavior;
- dashboard/API and concurrent-query impact;
- archive throughput/contention/reclamation and AI impact where applicable;
- representative CPU/core/memory/storage capacity curves;
- agreed acceptance thresholds;
- actual 24h/72h sustained runs.

A short/local run is measurement evidence only and must not be promoted to production sizing or release qualification.
