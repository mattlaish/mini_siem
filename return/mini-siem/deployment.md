# Deployment

1. Review `SOURCE_MANIFEST.json` and the repository-relative files under
   `source/` before applying them to the target mini-SIEM checkout.
2. Run the token tool with the database owner/setup identity:

   ```bash
   python3 tools/manage_dashboard_reader_token.py --db siem.db --initialize \
     create --principal operator-workspace --tenant default
   ```

3. Store the one-time token in the referenced secret manager. Do not place it
   in the binding, systemd unit, repository or logs.
4. For PostgreSQL, refresh the split-role grants after owner initialization.
5. Continue running the dashboard with its non-root service identity. The
   dashboard needs its existing database write access for durable cursor state;
   do not solve filesystem ownership by running the web process as root.
6. Terminate TLS at the approved origin, populate the deployment template, and
   complete Dashboard/G3 validation before setting `enabled=true`.

Token rotation accepts at most 24 hours overlap. Revoke the old token as soon
as the consumer has switched.

## Recovered schema and current-source upgrade

The five connector tables are dashboard_reader_tokens,
dashboard_export_counters, dashboard_export_records,
dashboard_export_snapshots and dashboard_export_snapshot_records. Run owner
initialization before the PostgreSQL runtime starts: missing tables fail the
existing runtime readiness check. Refresh grants with the existing reviewed
tools/postgres_privilege_boundary.py workflow. Runtime dashboard may update only
last_used_at on token rows; provisioning/revoke/rotate stay owner operations.
Do not pass owner credentials to the running dashboard.

The source payload contains the current complete application, not an overlay of
old dashboard.py/auth.py/db.py. Keep local auth/DB credential files and databases.
Source replacement is not automatic deployment. Back up, review and restart both
services with their existing least-privilege identities. Existing old-format
connector cursors require RESET_REQUIRED after this rebuild's visibility binding.

## Local bounds and known limitations

Per process: MINISIEM_DASHBOARD_RATE_PER_MINUTE=120 requests/60 seconds per
authenticated tenant/principal; MINISIEM_DASHBOARD_CONCURRENCY_PER_PRINCIPAL=2;
MINISIEM_DASHBOARD_GLOBAL_CONCURRENCY=8. There is no waiting queue: reject with
429 and integer Retry-After=1. Counters are in-memory/per-process, not shared HA
quotas. No independently configurable tenant-wide fairness quota is claimed.

MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS=16 per tenant/principal;
MINISIEM_DASHBOARD_SNAPSHOT_MAX_RECORDS=25000;
MINISIEM_DASHBOARD_SNAPSHOT_MAX_BYTES=67108864. Capacity exhaustion returns 503;
expired/missing snapshot returns 409. Snapshot/cursor TTL is 86400 seconds;
expired snapshots are pruned when creating a snapshot, not by a new daemon.
Pages cap at 500 records / 4 MiB, individual records 262144 bytes and provenance
65536 bytes. These snapshot caps do not bound all upstream native-table scanning
or persistent latest-record export-index growth. HISTORY retention, cleanup
deadline and crash guarantees require the work listed in open-gaps.md.

Server-wide execution deadline/cleanup bound: NOT_IMPLEMENTED by this recovered
reader. Do not infer one from the fixture client's 5/10/30-second limits.
Live TLS/ACL/load/backend qualification: NOT_RUN. Deployment owner must not enable
production solely on this return's offline PASS results.
