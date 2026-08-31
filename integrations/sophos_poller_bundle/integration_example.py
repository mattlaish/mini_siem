"""Adapter skeleton for embedding the bundled poller in another SIEM.

This example deliberately refuses to ingest until ``deliver_to_siem`` is
implemented. That prevents a first test run from advancing the Sophos cursor
without durably storing the corresponding events.
"""

import os
import sqlite3

from api_poller import PollerManager


DB_PATH = os.environ.get("SOPHOS_POLLER_DB", "sophos-poller.db")


def conn_factory():
    """Return a fresh connection; PollerManager closes every connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def resolve_secret(row):
    """Resolve the secret at token-fetch time; never log the returned value."""
    secret = os.environ.get("SOPHOS_CLIENT_SECRET", "")
    if not secret:
        raise RuntimeError("SOPHOS_CLIENT_SECRET is not configured")
    return secret


def deliver_to_siem(payload, connector, external_event_id):
    """Replace this with a durable API, queue, or database write.

    Return only after the target SIEM has accepted the event. Raise on any
    failure so the poller does not advance its cursor.
    """
    raise NotImplementedError("connect deliver_to_siem() to the target SIEM")


def ingest_event(event):
    connector = event.get("_connector") or "sophos-central"
    payload = event.get("_json", event)
    if isinstance(payload, dict) and event.get("_endpoint_ip"):
        payload = dict(payload)
        payload.setdefault("endpoint_ip", event["_endpoint_ip"])
    external_event_id = payload.get("id", "") if isinstance(payload, dict) else ""
    deliver_to_siem(payload, connector, external_event_id)


def start():
    manager = PollerManager(
        conn_factory=conn_factory,
        ingest_fn=ingest_event,
        resolve_secret_fn=resolve_secret,
    )
    manager.start()
    return manager


if __name__ == "__main__":
    raise SystemExit(
        "Import start() from your SIEM service after implementing "
        "deliver_to_siem(); do not run this skeleton unchanged."
    )
