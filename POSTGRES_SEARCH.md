# PostgreSQL search and layout — 2026-11-06

Status: **implemented in source, not exercised against PostgreSQL or benchmarked**.
No speedup, partition winner, live install or sustained ingest rate is claimed.
SQLite keeps its existing schema, writes, and default search scope.

## Search behavior

- The PostgreSQL log screen and paged Log Search API default to the last 24 hours.
  Explicit From/To values override the default. Use **All retained logs**
  (`scope=all`) for an intentional wide search. Event-ID drilldowns remain
  unrestricted by default time. Non-paged API and direct export callers keep
  their old scope unless they request `scope=recent`.
- Paged responses with an implicit range include `window.from` and `window.to`.
  Send these back as `from` and `to` along with `snapshot` and `offset` when
  appending pages. The ID watermark comes from the raw evidence primary key,
  not from a max-ID search across time partitions.
- Source/destination IP and CIDR use native INET; the PostgreSQL search screen
  accepts typed port values and ranges such as `53` or `8000-8099`.
  Common valid IP/port aliases are resolved on ingest; transport sender identity
  remains separate. Custom aliases and conflicting text matches retain fallback.
- Multiple positive exact AND filters use one containment predicate against
  `search_fields`, built using the same case-folding/truncation as the field
  table. Original `fields`, `message` and raw evidence are not rewritten.
  Rows without that normalized projection use the legacy field table.
  Prefix, substring, OR, exclusion and extracted-field sorting use that table.
- Field prefix indexes and a partial trigram index cover `query` and `url`
  contains searches. Other fields still support contains without that index.
  Message word/prefix-of-token search remains full-text, not substring search.
- `GET /api/logs/facets?field=query` returns up to 200 normalized field values
  with distinct event counts in the selected time range (same default/scope
  rules). This is not pre-aggregated and arbitrary all-history counts can grow
  more expensive. Use bounded scopes unless investigating across history.

## Fresh PostgreSQL installation

Month remains the default; no measured reason to prefer week or day yet.
Before initializing a **fresh** database, set the `postgres.partition_granularity`
value in database config to `month`, `week`, or `day`. Both event and field
partitions follow that layout. The owner initializer creates the next three
months of coverage; the existing maintenance timer extends both tables.
The layout of existing event partitions is not changed by modifying config.
No partition drops, expiration, or retention changes are introduced.

Owner initialization needs the PostgreSQL `pg_trgm` extension to be available
and the owner/setup role allowed to create it, or it must already be installed.
Run owner initialization and refresh split-role grants before starting new
listener/dashboard runtime. Runtime roles still cannot apply DDL.

Older PostgreSQL installations keep their existing event partitions and physical
field table. The owner initializer adds compatible search columns/indexes;
it does not repartition populated data or copy raw evidence. Undated legacy
field rows are matched via a sentinel fallback. Large index builds need a
maintenance plan; do not treat owner initialization as online migration.

System Health warns about event rows or **dated** field rows in the default
partitions. Review time coverage and bad/late/future event timestamps; overlapping
rows must be moved into the right partition before it can be attached. No data is
automatically deleted or moved by this warning.

## Optional future benchmark

Use only a dedicated local PostgreSQL test cluster, bound to loopback and started
with `minisiem.benchmark=on`; the benchmark refuses a server without that marker.
Use an isolated owner test login able to create a database, and supply any
password through the test process environment. The tool creates a new database
with a random name; it does not drop or truncate any database.

```text
python -B tools/postgres_search_benchmark.py --port TEST_PORT --layout month --json-out month.json
python -B tools/postgres_search_benchmark.py --port TEST_PORT --layout week --json-out week.json
python -B tools/postgres_search_benchmark.py --port TEST_PORT --layout day --json-out day.json
```

Use the same row counts and repeats across runs. Hot rows stay fixed when older
history is added; reports record route p50/p95, actual SQL plans/buffers/relations,
table/index sizes and serial batch-write throughput. Synthetic distribution and
warm-cache measurements are not production ingest/latency qualification.
