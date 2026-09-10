# mini-SIEM Testing Truth Boundary

This file records the **Performance Phase 6** verification state. A listed **PASS**
means the check was actually executed against this source tree and, for the final
release gate, repeated from a clean extraction of the release ZIP. **DEFERRED / NOT
RUN** and **BLOCKED / NOT RUN** are never counted as passes.

## Phase 6 required checks

| Check | State | Notes |
|---|---|---|
| Phase-6 focused regression | PASS | `tests/test_evidence_archive_phase6.py`: 7 passed |
| Selected non-Flask regression | PASS | 81 passed across DB, ingest, Phase 3/4/5/6, SQL/search helpers, Timeline, investigation, archive, telemetry and live-refresh modules |
| Archive disabled by default | PASS | default config has archive OFF; maintenance does not age-delete evidence |
| Exact lossless archive dedup | PASS | exact payload/field duplicates share one archived payload while every original log ID + `received_at` occurrence is preserved |
| Archive copy idempotence | PASS | already-cataloged original log IDs are not archived repeatedly |
| Verified move semantics | PASS | hot copy eviction occurs only after sealed segment creation/checksum/catalog/reopen verification; global evidence counters/rollups and IOC evidence remain |
| Archive text/structured/field/time compatibility | PASS | archive-compatible `logs`/`log_fields` views preserve combined query semantics |
| Archive checksum tamper detection | PASS | catalog verification detects a modified sealed segment |
| Archive query truth boundary | PASS | source/structure checks enforce explicit archive availability failure rather than silent partial history; Flask route execution remains blocked by missing Flask in this environment |
| Query telemetry fail-open boundary | PASS | telemetry remains coarse/observational and cannot modify query predicates/results; telemetry failures are tolerated |
| Non-destructive SQLite maintenance | PASS | PASSIVE checkpoint, bounded incremental vacuum where already supported, optimize, freelist/free-space visibility, and rate-limited quick-check; no live age-delete or automatic full `VACUUM` |
| Operational health/backpressure signals | PASS | queue pressure drives `HEALTHY` / `DEGRADED` / `OVERLOADED`; health output is observation-only and contains no enforcement action |
| IOC architecture freeze | PASS | Phase 6 does not make a new embedded-vs-external IOC architecture decision |
| Python compileall | PASS | `python3 -m compileall -q .` |
| Dashboard/Health JavaScript syntax | PASS | `static/csrf.js`, `templates/index.html` inline JS, and `templates/health.html` inline JS via `node --check` |
| Shell syntax | PASS | `db-maintenance.sh`, `install-services.sh`, and `install-service.sh` via `bash -n` |
| Static security scan | PASS | 24 Python files scanned; 0 findings |
| 5,000-event bounded SQLite ingest smoke | PASS | 5,000 accepted/persisted/processed; 15,000 field rows; 5,000 rollup count; 50 DB batches averaging 100; zero ingest/DB-queue drops or processing/DB failures |
| 20,000-occurrence archive/dedup smoke | PASS | 20,000 archived occurrences, 100 exact unique payloads, 19,900 duplicate occurrences, one sealed segment, checksum/readability verification PASS; copy mode retained all 20,000 hot rows |
| Full Flask-dependent pytest collection | BLOCKED / NOT RUN | full `pytest -q` attempted; collection stops because Flask is absent in `tests/test_dashboard_routes.py` and `tests/test_log_search_logic.py` |
| Live PostgreSQL connection/session profile | DEFERRED / NOT RUN | `psycopg2` and PostgreSQL server/client executables are unavailable in packaging environment |
| PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` matrix | DEFERRED / NOT RUN | guarded Phase-4/5 PostgreSQL harnesses remain available but need a disposable real PostgreSQL instance |
| Production archive/re-hydration soak on large persistent storage | DEFERRED / NOT RUN | requires target disk/filesystem, representative evidence volume, backup/archive custody and operator recovery procedures |
| Production socket/forwarder sustained-burst soak | DEFERRED / NOT RUN | requires target network/storage/downstream infrastructure |

## Final source-tree verification — 2026-09-04

- Selected non-Flask regression: **81 passed**.
- Dedicated Phase-6 archive/evidence tests: **7 passed**.
- Full `PYTHONPATH=. pytest -q` was attempted and stopped during collection with
  `ModuleNotFoundError: No module named 'flask'` in `tests/test_dashboard_routes.py`
  and `tests/test_log_search_logic.py`. This is **BLOCKED / NOT RUN**, not a pass.
- `python3 -m compileall -q .`: **PASS**.
- JavaScript syntax: `static/csrf.js`, Dashboard inline script, and Health inline
  script: **PASS**.
- Shell syntax: `db-maintenance.sh`, `install-services.sh`, `install-service.sh`:
  **PASS**.
- `python3 security_static_scan.py`: **PASS**, 24 files scanned, 0 findings.
- Bounded 5,000-event SQLite ingest smoke: **5,000 accepted, 5,000 persisted,
  5,000 processed, 15,000 normalized field rows, 5,000 hourly rollup count,
  50 DB batches, batch average 100.0, zero ingest drops, zero DB-queue drops,
  zero processing failures, zero DB failures**. The source-tree temporary-filesystem
  run measured about **8,392 events/s**, commit average **9.805 ms**, p50
  **8.712 ms**, p95 **10.317 ms**. These are engineering smoke numbers only.
- Bounded archive/dedup smoke used **20,000 occurrences comprising 100 exact unique
  payloads**. The sealed archive contained **20,000 occurrence rows, 100 payload rows,
  200 payload-field rows, and 19,900 duplicate occurrences**, with catalog checksum /
  readability verification passing. Copy mode correctly kept all 20,000 hot rows.
  The source-tree temporary-filesystem run archived at about **12,923 occurrences/s**
  and produced a ~1.68 MiB segment. This is a regression signal, not a capacity claim.
- `psycopg2`, `psql`, `postgres`, `initdb`, and `pg_ctl` are unavailable, so live
  PostgreSQL validation remains **DEFERRED / NOT RUN**.

## Archive operator checks

Manual bounded archive cycle:

```bash
python3 tools/archive_now.py --config ./db-config.json
```

Verify every cataloged sealed segment:

```bash
python3 tools/archive_verify.py --config ./db-config.json
```

A missing or corrupt segment must be treated as an evidence-availability incident.
Do not convert that condition into an empty historical search result.

## PostgreSQL validation command

After pointing a **disposable** `db-config.json` at PostgreSQL:

```bash
python3 tools/postgres_phase5_validation.py \
  --config ./db-config.json \
  --rows 100000 \
  --confirm-test-db \
  --json-out /tmp/minisiem-pg-phase5-plans.json
```

The harness is guarded against obvious production database names and checks the bounded
session profile plus the existing plan matrix for FTS/GIN, pg_trgm substring search,
field exact/prefix, Source/Host/Destination exact/prefix, time+structured combinations,
text AND field semantics, and cursor pagination. The harness existing in the repository
does **not** mean those PostgreSQL plans have been validated here.

## Performance-number policy

Temporary-filesystem SQLite rates, archive/dedup rates, IOC timings, and query/commit
latencies are engineering smoke data only. They are useful for same-host regression
comparison but are not production capacity claims. Production sizing requires actual
storage, event shapes, rules/IOC load, forwarding destinations, archive custody/backup,
and the selected database backend.

## PostgreSQL Migration Test Coverage Notes

Additional validation areas identified:

- PostgreSQL startup behavior
- database readiness handling
- existing schema detection
- identity/bootstrap preservation
- migration rollback behavior
- source artifact integrity
