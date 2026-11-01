# Sophos Central Poller Integration Bundle

This directory is a portable snapshot of mini-SIEM's production-verified
Sophos Central SIEM API poller. The owner confirmed that the original
integration collected 4,739 real events from 2026-08-05 through 2026-08-20.

The bundle keeps the same `PollerManager` callback contract and the same
`api_pollers` schema. It contains no credentials and performs no production
network calls during its tests.

## Contents

- `api_poller.py` — OAuth2, Whoami, regional-host, tenant-header, cursor, and
  polling implementation.
- `schema.sqlite.sql` / `schema.postgresql.sql` — matching poller state schema.
- `sophos-poller.example.json` — safe configuration example with no secret.
- `integration_example.py` — callback adapter skeleton.
- `test_bundle.py` — offline HTTP-mocked verification of the Sophos flow.

## Required Sophos configuration

| Field | Value |
|---|---|
| `auth_scheme` | `oauth2_sophos` |
| `token_url` | `https://id.sophos.com/api/v2/oauth2/token` |
| `whoami_url` | `https://api.central.sophos.com/whoami/v1` |
| `events_url` | `/siem/v1/events` |
| `tenant_header` | blank; the poller selects `X-Tenant-ID` automatically |
| `scope` | `token` |
| `client_id` | Sophos API credential client ID |
| `client_secret` | supplied by `resolve_secret_fn`; never place it in this bundle |

The poller sends the JWT as `Authorization: Bearer <token>` to Whoami without
an `X-*-ID` header. It then uses the returned principal ID and
`apiHosts.dataRegion` for the events request.

## Integration steps

1. Copy this entire directory into the target SIEM.
2. Apply the matching schema to the target state database.
3. Insert one disabled `api_pollers` row using the values above. Keep the
   client secret in the target SIEM's secret store.
4. Implement the three callbacks shown in `integration_example.py`:
   - `conn_factory()` returns a new closeable connection.
   - `resolve_secret(row)` returns the plaintext secret only when requested.
   - `ingest_event(event)` durably accepts one event or raises an exception.
5. Start one `PollerManager` in the SIEM service process.
6. Enable the poller only after the ingest callback and deduplication have been
   tested.
7. Confirm `last_poll_at`, `last_error`, `pulled_count`, and `cursor` change as
   expected.

Example startup:

```python
from api_poller import PollerManager

manager = PollerManager(
    conn_factory=conn_factory,
    ingest_fn=ingest_event,
    resolve_secret_fn=resolve_secret,
)
manager.start()
```

## Callback and database contract

`conn_factory` is called from background threads and must return a fresh
connection. Do not return one process-global connection. Rows must be
convertible with `dict(row)`. The connection must provide `execute()`,
`commit()`, and `close()`.

The bundled SQL uses `?` placeholders because that is the mini-SIEM DB
abstraction contract. Native SQLite satisfies it directly. A PostgreSQL
consumer must use mini-SIEM's compatibility wrapper or provide an equivalent
adapter that translates `?` to the driver's placeholder style.

`ingest_fn` receives:

```python
{
    "_connector": "sophos-central",
    "_endpoint_ip": "optional endpoint IP",
    "_json": {"id": "Sophos event UUID", "...": "full event"}
}
```

The callback must return only after durable acceptance. If it raises, the
poller records the error and does not save the next cursor.

## Important operational notes

### Deduplication is required

The poller ingests items before saving `next_cursor`. A crash after some items
are stored but before the cursor update causes that page to be replayed. Use a
unique key such as `(connector, Sophos event id)` and make ingestion idempotent.
Sophos documents the event `id` as a UUID.

### A partial page can replay

`ingest_batch` calls the callback one item at a time. If item 50 fails, items
1-49 may be delivered again. Do not advance an independent target cursor from
inside the callback.

### First-run time parameter

Sophos SIEM v1 uses `from_date`, not `from`, as its Unix UTC starting-time
parameter. It is ignored when a cursor exists and must be within the last 24
hours. This portable bundle uses `from_date`. The original deployed mini-SIEM
file remains unchanged because its established cursor path is production
verified.

### Secret handling

Do not place a client secret in source code, JSON examples, logs, exceptions,
or this schema. Resolve it at token-fetch time from the target SIEM's encrypted
store, environment injection, or external secret manager. Database encryption
does not protect a secret from an attacker who also controls the running SIEM
process and its decryption key.

### Token lifetime

This snapshot assumes a 3,600-second token lifetime and refreshes five minutes
early. If Sophos changes the lifetime or the response supplies `expires_in`,
prefer using the returned value, with a safe early-refresh margin.

### Concurrency and lifecycle

Each enabled row runs in its own daemon thread, and the manager reconciles DB
changes every ten seconds. Callbacks therefore must be thread-safe. The current
manager is process-lifetime oriented and does not expose a public graceful-stop
method; daemon threads stop when the process exits.

### Error and retry behavior

HTTP and callback errors are stored in `last_error`. Retry occurs on the next
configured interval; there is no exponential backoff or dead-letter queue.
Monitor repeated errors and Sophos rate-limit responses.

### URL trust boundary

The table controls token, Whoami, and events URLs. Only trusted administrators
should edit these values. A reusable implementation should apply an explicit
allowlist for Sophos hosts if untrusted users can configure connectors.

## Offline validation

From this directory, run:

```bash
python3 -m unittest -v test_bundle.py
```

The test mocks all HTTP calls. It verifies the token request, Bearer Whoami
request, regional events host, automatic tenant header, cursor, and official
`from_date` parameter without contacting Sophos.
