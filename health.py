"""
mini-SIEM health metrics
========================
Collects system and SIEM-specific health indicators for the /health
page. Designed to need NO third-party packages on Linux — CPU, memory,
disk usage, UDP drop counters and load average all come from /proc and
the standard library. If psutil happens to be installed, disk-I/O and
network-I/O rates are added; if not, those are reported as unavailable
rather than failing.

Everything here is read-only and cheap.
"""

import os
import shutil
import time
from datetime import datetime, timedelta, timezone

try:
    import psutil  # optional, only for disk/net I/O rates
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False


# --------------------------------------------------------------------------
# CPU (via /proc/stat delta) — Linux
# --------------------------------------------------------------------------

def _read_cpu_times():
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()
        vals = [float(x) for x in parts[1:]]
        # user nice system idle iowait irq softirq steal ...
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        total = sum(vals)
        iowait = vals[4] if len(vals) > 4 else 0.0
        return total, idle, iowait
    except Exception:
        return None


def cpu_percent(sample=0.25):
    a = _read_cpu_times()
    if not a:
        return {"available": False}
    time.sleep(sample)
    b = _read_cpu_times()
    if not b:
        return {"available": False}
    total_d = b[0] - a[0]
    idle_d = b[1] - a[1]
    iowait_d = b[2] - a[2]
    if total_d <= 0:
        return {"available": False}
    busy = (1 - idle_d / total_d) * 100
    iowait = (iowait_d / total_d) * 100
    return {"available": True, "percent": round(busy, 1), "iowait_percent": round(iowait, 1)}


def load_average():
    try:
        one, five, fifteen = os.getloadavg()
        cores = os.cpu_count() or 1
        return {"available": True, "one": round(one, 2), "five": round(five, 2),
                "fifteen": round(fifteen, 2), "cores": cores}
    except Exception:
        return {"available": False}


# --------------------------------------------------------------------------
# Memory (via /proc/meminfo) — Linux
# --------------------------------------------------------------------------

def memory_info():
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k.strip()] = int(v.strip().split()[0]) * 1024  # kB -> bytes
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = total - avail
        pct = (used / total * 100) if total else 0
        return {"available": True, "total": total, "used": used,
                "free": avail, "percent": round(pct, 1)}
    except Exception:
        return {"available": False}


# --------------------------------------------------------------------------
# Disk usage (stdlib, cross-platform) for the filesystem holding the DB
# --------------------------------------------------------------------------

def disk_usage(path):
    try:
        target = path if os.path.exists(path) else os.path.dirname(os.path.abspath(path)) or "/"
        total, used, free = shutil.disk_usage(target)
        pct = (used / total * 100) if total else 0
        return {"available": True, "total": total, "used": used, "free": free,
                "percent": round(pct, 1), "path": target}
    except Exception:
        return {"available": False}


# --------------------------------------------------------------------------
# Disk / net I/O rates (psutil if present)
# --------------------------------------------------------------------------

_io_prev = {"t": None, "disk_r": 0, "disk_w": 0, "net_s": 0, "net_r": 0}


def io_rates():
    if not _HAS_PSUTIL:
        return {"available": False, "reason": "install psutil for I/O rates: pip install psutil"}
    try:
        now = time.time()
        d = psutil.disk_io_counters()
        n = psutil.net_io_counters()
        prev = _io_prev.copy()
        _io_prev.update({"t": now, "disk_r": d.read_bytes, "disk_w": d.write_bytes,
                         "net_s": n.bytes_sent, "net_r": n.bytes_recv})
        if prev["t"] is None:
            return {"available": True, "warming_up": True}
        dt = now - prev["t"]
        if dt <= 0:
            return {"available": True, "warming_up": True}
        return {
            "available": True,
            "disk_read_bps": (d.read_bytes - prev["disk_r"]) / dt,
            "disk_write_bps": (d.write_bytes - prev["disk_w"]) / dt,
            "net_sent_bps": (n.bytes_sent - prev["net_s"]) / dt,
            "net_recv_bps": (n.bytes_recv - prev["net_r"]) / dt,
        }
    except Exception as exc:
        return {"available": False, "reason": str(exc)}


# --------------------------------------------------------------------------
# UDP drop counters (via /proc/net/snmp) — the SIEM-critical one
# --------------------------------------------------------------------------

def udp_stats():
    try:
        header = values = None
        with open("/proc/net/snmp") as f:
            for line in f:
                if line.startswith("Udp:"):
                    if header is None:
                        header = line.split()[1:]
                    else:
                        values = line.split()[1:]
                        break
        if not header or not values:
            return {"available": False}
        data = dict(zip(header, (int(v) for v in values)))
        return {
            "available": True,
            "in_datagrams": data.get("InDatagrams", 0),
            "in_errors": data.get("InErrors", 0),
            "rcvbuf_errors": data.get("RcvbufErrors", 0),
            "drops": data.get("RcvbufErrors", 0) + data.get("InErrors", 0),
        }
    except Exception:
        return {"available": False}


# --------------------------------------------------------------------------
# SIEM data-plane metrics (from the DB)
# --------------------------------------------------------------------------

def _count_since(conn, iso_cutoff):
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM logs WHERE received_at >= ?", (iso_cutoff,)).fetchone()
    return row["c"] if isinstance(row, dict) else row[0]


def siem_metrics(conn, db_config):
    now = datetime.now(timezone.utc)
    min_cut = (now - timedelta(minutes=1)).isoformat()
    hour_cut = (now - timedelta(hours=1)).isoformat()

    total = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()
    total = total["c"] if isinstance(total, dict) else total[0]
    alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
    alerts = alerts["c"] if isinstance(alerts, dict) else alerts[0]

    last_min = _count_since(conn, min_cut)
    last_hour = _count_since(conn, hour_cut)

    # DB size
    db_size = None
    backend = db_config.get("backend", "sqlite")
    if backend == "sqlite":
        try:
            db_size = os.path.getsize(db_config["sqlite"]["path"])
        except Exception:
            db_size = None
    else:
        try:
            row = conn.execute("SELECT pg_database_size(current_database()) AS s").fetchone()
            db_size = row["s"] if isinstance(row, dict) else row[0]
        except Exception:
            db_size = None

    return {
        "backend": backend,
        "total_logs": total,
        "total_alerts": alerts,
        "events_last_min": last_min,
        "events_last_hour": last_hour,
        "events_per_sec_1m": round(last_min / 60.0, 2),
        "db_size_bytes": db_size,
    }


def collect(conn, db_config):
    """One-shot snapshot of everything for the /api/health endpoint."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu": cpu_percent(),
        "load": load_average(),
        "memory": memory_info(),
        "disk": disk_usage(
            db_config["sqlite"]["path"] if db_config.get("backend") == "sqlite" else "."),
        "io": io_rates(),
        "udp": udp_stats(),
        "siem": siem_metrics(conn, db_config),
        "has_psutil": _HAS_PSUTIL,
    }
