# PostgreSQL search and layout — 2026-11-06

The PostgreSQL dashboard and ingest changes below were tested on an isolated
PostgreSQL 16 instance. Sustained ingest rate and production search latency
remain unmeasured. SQLite keeps its storage layout and default Log Search scope.

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
  `search_fields`. Exact OR uses per-value containment predicates. Exclusion
  applies containment to the candidate rows, including rows where the
  field is absent. PostgreSQL may use GIN for positive predicates when
  selective. Rows without a normalized projection use the legacy field index.
  Prefix, substring and extracted-field sorting continue to use the field table.
- Indexed command lines and script blocks retain up to 16,384 characters.
  Other fields retain their 300-character indexed limit. PostgreSQL uses a
  bounded prefix key and a digest with an exact value recheck. Re-index older
  retained logs to recover the longer fields from their original evidence.
- Field prefix indexes and a partial trigram index cover `query` and `url`
  contains searches. Other fields still support contains without that index.
- Newest-first pages with `*text*` (contains) field filters first check the
  newest 50,000 events of the window row by row (other filters still apply)
  and stop at the page size. Those events are the start of the result order,
  so a full page found there is exactly the first page. If the window is
  smaller than that, the answer is also exact. Otherwise (rare matches, deep
  pages, OR mode, other sort orders) the indexed query runs as before.
  Message word/prefix-of-token search remains full-text, not substring search.
- `GET /api/logs/facets?field=query` returns up to 200 normalized field values
  with distinct event counts in the selected time range (same default/scope
  rules). This is not pre-aggregated and arbitrary all-history counts can grow
  more expensive. Use bounded scopes unless investigating across history.
  Log Search shows it as **Top values** (toolbar button, or "top values" next
  to a field in an expanded event); clicking a value filters by it, "not"
  excludes it. Both actions compare the selected value literally, including
  leading exclamation marks and trailing asterisks. SQLite answers the same
  request from its field table.

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
partitions, and the dashboard raises one alert ("Events outside time
partitions", rule `storage_default_partition`) when they first appear; it
checks every 10 minutes and alerts again only after the partitions were empty. Review time coverage and bad/late/future event timestamps; overlapping
rows must be moved into the right partition before it can be attached. No data is
automatically deleted or moved by this warning.

## PostgreSQL evidence and index upgrade

For an existing database, stop ingest and Dashboard, take a backup, and run the
owner upgrade before refreshing split-role grants and restarting. Migration 44
compares the original text against the projection, builds partition-local
full-text indexes from search terms, and removes the verified duplicate
projection columns. It stops if it detects mismatched or missing evidence.
Plan a maintenance window for the comparison, row updates and index builds.
The raw log table remains the evidence authority and supports time-based
archive and AI lookup. New ID lookups use the stored partition key. Legacy
IDs without a key continue to work through the previous lookup path.

Nine event indexes were removed from the fresh and upgrade layouts. Native IP
B-trees support CIDR bounds, and typed ports, time, full text and normalized
JSONB retain their search indexes. PostgreSQL may choose another plan for a
broad filter. A loaded-system baseline is still needed for production planning.

For new events, a device clock ahead of receipt or more than 30 days behind
uses receipt time as the searchable event time. Both the original device
timestamp and the parsed device time are available in the event view. Existing
events remain in their current partitions.

## Dashboard statistics and query limits

- Home and System Health display an estimated PostgreSQL log total from table
  statistics. It can lag ingest and shows as pending while the table has data
  but has no usable estimate. The first-use prompt checks whether any logs exist.
  SQLite continues to report an exact total.
- The PostgreSQL silent-source list reads a summary of each source's latest
  receipt time. The source is the same `logs.source_ip` used by the previous
  query. The insert trigger updates the summary in the log transaction and
  stores receipt times at minute precision. Archive operations do not rewind
  the last observed receipt time.
- `postgres.dashboard_statement_timeout_ms` in database config defaults to
  `30000` and accepts `1000` through `60000`. It limits each SQL statement in an
  interactive Dashboard request. The UI suggests narrowing the search after a
  query timeout. Ingest, schema maintenance and background work use their
  existing database connections.
- AI Chat selects log and alert evidence from the latest 24 hours on both
  backends. Use Log Search and an explicit time range for older evidence.
- For an existing PostgreSQL installation, run the documented owner upgrade
  so migration 43 creates the summary and backfills the prior 14 days. Apply
  the split-role grant refresh before restarting. The first backfill reads the
  recent raw logs once. Fresh installations get the summary and grants during
  setup. Raw evidence and retention remain intact.

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

## Measure a running deployment (step 0)

`tools/postgres_search_measure.py` is read-only: every connection it opens is
read-only at the server (`default_transaction_read_only`), with a 60 s
statement limit and a 2 s lock wait. It records server settings, the storage
layout (field table split or not, partition grain, DEFAULT partition rows),
table/index sizes, indexes never used, events per day for 14 days, peak
arrival rate, fields per log, and timed runs plus `EXPLAIN (ANALYZE, BUFFERS)`
of typical searches built from values in your last 24 hours (exact, three
exact, starts-with, contains, OR/exclusion, CIDR, host prefix, port, message
word, and all-history variants). Run it from the deployed source tree, at a
quiet hour, with the dashboard's credential file:

```text
python -B tools/postgres_search_measure.py --db-config db-config.json \
    --db-credentials <dashboard credential file> --out measure.json \
    --search "<a Log Search URL your team uses>" --search "<another>"
```

The screen summary contains no event values and can be shared. The JSON file
holds full plans with sample values from your logs (addresses, host names,
field values); review it before sharing. `--skip-all-history` leaves out the
all-history searches on a busy server; `--end` measures another day.
