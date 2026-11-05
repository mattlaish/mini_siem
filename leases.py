"""Process-safe job leases: each background job runs in one process at a time.

A lease is a row in ``worker_leases`` naming a job ("ticket-worker",
"poller:3", ...), its current holder and an expiry time. A process claims or
renews a lease with one conditional UPDATE, so when several dashboard
processes (or hosts sharing one PostgreSQL database) start the same workers,
only the holder runs each job. If the holder stops renewing (crash, shutdown,
network loss) another process takes over once the lease expires. Per-item
leases such as one per cloud connection also spread work across processes.

Leases are a coordination aid, not a lock manager: TTLs are several times a
job's interval so a slow cycle cannot lose its lease mid-run, and hosts are
expected to have roughly synchronized clocks (NTP).

Databases created before this table existed keep the previous single-process
behavior (every job runs locally) and log a warning until the owner runs
schema initialization.
"""
import os
import socket
import threading
import time
import uuid


def default_owner():
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"


def _missing_table(exc):
    text = str(exc).lower()
    return "worker_leases" in text and ("no such table" in text or "does not exist" in text)


class LeaseKeeper:
    def __init__(self, get_conn, owner=None, clock=time.time):
        self.get_conn = get_conn
        self.owner = owner or default_owner()
        self.clock = clock
        self._held = {}          # name -> expiry of our last successful claim
        self._lock = threading.Lock()
        self.unavailable = False  # table missing: single-process fallback
        self.last_error = None

    def hold(self, name, ttl):
        """Claim or renew ``name`` for ``ttl`` seconds. True when this process
        holds it and should run the job now."""
        now = self.clock()
        expires = now + max(1.0, float(ttl))
        conn = None
        try:
            conn = self.get_conn()
            conn.execute(
                "INSERT INTO worker_leases(name, owner, expires_at, acquired_at, renewed_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(name) DO NOTHING",
                (name, self.owner, expires, now, now))
            cur = conn.execute(
                "UPDATE worker_leases SET owner=?, expires_at=?, renewed_at=?, "
                "acquired_at=CASE WHEN owner=? THEN acquired_at ELSE ? END "
                "WHERE name=? AND (owner=? OR expires_at < ?)",
                (self.owner, expires, now, self.owner, now, name, self.owner, now))
            held = cur.rowcount == 1
            conn.commit()
        except Exception as exc:  # noqa: BLE001 - a job must never crash its loop
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:  # noqa: BLE001
                    pass
            if _missing_table(exc):
                if not self.unavailable:
                    print("[leases] worker_leases table missing; running every job in this process. "
                          "Run schema initialization with the owner identity before starting a second process.")
                self.unavailable = True
                return True
            # Unknown database state: skip this cycle rather than risk running
            # a job another process may hold. The next cycle retries.
            self.last_error = f"{type(exc).__name__}: {exc}"
            held = False
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        with self._lock:
            if held:
                self._held[name] = expires
            else:
                self._held.pop(name, None)
        return held

    def holds(self, name):
        """Whether our last claim on ``name`` is still unexpired (no I/O)."""
        if self.unavailable:
            return True
        with self._lock:
            return self._held.get(name, 0) > self.clock()

    def release(self, name):
        with self._lock:
            self._held.pop(name, None)
        if self.unavailable:
            return
        conn = None
        try:
            conn = self.get_conn()
            conn.execute("UPDATE worker_leases SET expires_at=0 WHERE name=? AND owner=?",
                         (name, self.owner))
            conn.commit()
        except Exception:  # noqa: BLE001 - expiry releases it anyway
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass

    def release_all(self):
        with self._lock:
            names = list(self._held)
        for name in names:
            self.release(name)

    def binding(self, name, ttl):
        """A zero-argument callable for a worker loop: claim/renew then run."""
        return lambda: self.hold(name, ttl)


def lease_status(conn, now=None):
    """All leases with plain holder state, for System Health."""
    now = now if now is not None else time.time()
    rows = conn.execute(
        "SELECT name, owner, expires_at, acquired_at, renewed_at FROM worker_leases ORDER BY name").fetchall()
    out = []
    for r in rows:
        r = dict(r)
        expires = float(r["expires_at"] or 0)
        out.append({"job": r["name"], "owner": r["owner"],
                    "state": "held" if expires > now else "free",
                    "expires_in_seconds": max(0, round(expires - now)),
                    "held_since": r["acquired_at"], "renewed_at": r["renewed_at"]})
    return out
