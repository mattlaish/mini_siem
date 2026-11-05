"""Machine capacity scan and ingest process/thread recommendation.

``scan()`` reads what this machine actually offers the listener: logical
CPUs, the CPU affinity mask, container (cgroup) CPU quota and memory limit,
available memory, current load, free disk next to a SQLite database and
whether PostgreSQL runs on the same host. ``recommend()`` turns that into a
number of ingest processes, threads per process and queue size, with the
reasons behind each limit. ``ingest_settings()`` resolves what the listener
will run from db-config.json ("ingest" section, where "processes" may be
"auto") and command-line overrides.

Optional, slower measurements: ``measure_process_memory()`` starts one
Python process that imports the ingest code and reports its resident memory;
``benchmark()`` times parsing, field extraction and rule evaluation in this
process. Neither includes database write time, which is usually the real
ceiling: treat the throughput figure as a CPU upper bound, not a promise.
"""
import os
import platform
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROCESS_MB = 90        # one ingest process when not measured
MIN_PROCESS_MB = 60            # floor: a running process adds DB driver buffers and caches
IOC_KB = 1.0                   # each process keeps its own in-memory indicator index
DASHBOARD_MB = 250             # web console + background workers
OS_HEADROOM_MB = 512
QUEUE_ITEM_KB = 2              # queued syslog line + parsed event, typical
DEFAULT_QUEUE_SIZE = 10000
MAX_PROCESSES = 16             # one receiving process routes to all of them
UDP_BUFFER_KB = 4096           # requested per UDP socket; Linux caps it at net.core.rmem_max
LIMITS = {"processes": (1, 32), "threads": (1, 16), "queue_size": (100, 200000), "udp_buffer_kb": (64, 262144)}
DEFAULTS = {"processes": 1, "threads": 2, "queue_size": DEFAULT_QUEUE_SIZE, "udp_buffer_kb": UDP_BUFFER_KB}


# ---------------------------------------------------------------- scanning

def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def cgroup_cpu_limit(root="/sys/fs/cgroup"):
    """CPUs allowed by a container quota, or None when unlimited/unknown."""
    v2 = _read(os.path.join(root, "cpu.max"))
    if v2:
        parts = v2.split()
        if len(parts) >= 2 and parts[0] != "max":
            try:
                return int(parts[0]) / int(parts[1])
            except (ValueError, ZeroDivisionError):
                return None
        return None
    for base in (os.path.join(root, "cpu"), os.path.join(root, "cpu,cpuacct"), root):
        quota, period = _read(os.path.join(base, "cpu.cfs_quota_us")), _read(os.path.join(base, "cpu.cfs_period_us"))
        if quota and period:
            try:
                q, p = int(quota), int(period)
            except ValueError:
                return None
            return q / p if q > 0 and p > 0 else None
    return None


def cgroup_memory_limit_mb(root="/sys/fs/cgroup"):
    """Memory allowed by a container limit in MB, or None when unlimited."""
    for path in (os.path.join(root, "memory.max"), os.path.join(root, "memory", "memory.limit_in_bytes")):
        value = _read(path)
        if value is None:
            continue
        if value == "max":
            return None
        try:
            limit = int(value)
        except ValueError:
            return None
        return None if limit >= 1 << 60 else limit // (1024 * 1024)   # v1 "unlimited" is a huge number
    return None


def memory_info():
    """(total_mb, available_mb); either may be None if the platform hides it."""
    meminfo = _read("/proc/meminfo")
    if meminfo:
        values = {}
        for line in meminfo.splitlines():
            key, _, rest = line.partition(":")
            try:
                values[key] = int(rest.split()[0]) // 1024
            except (IndexError, ValueError):
                pass
        return values.get("MemTotal"), values.get("MemAvailable", values.get("MemFree"))
    if sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.ullTotalPhys // 2**20, status.ullAvailPhys // 2**20
        except Exception:  # noqa: BLE001 - report unknown instead of failing
            pass
        return None, None
    if sys.platform == "darwin":
        try:
            total = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                                       text=True, timeout=5).stdout.strip()) // 2**20
            return total, None
        except Exception:  # noqa: BLE001
            pass
    return None, None


def udp_info(proc_root="/proc"):
    """Kernel UDP receive drops and buffer ceilings (Linux). The counters are
    host-wide since boot and include every UDP service on the machine."""
    snmp = _read(os.path.join(proc_root, "net", "snmp"))
    out = {"receive_buffer_errors": None, "receive_errors": None,
           "rmem_max_kb": None, "rmem_default_kb": None}
    if snmp:
        lines = [line.split() for line in snmp.splitlines() if line.startswith("Udp:")]
        if len(lines) >= 2:
            row = dict(zip(lines[0][1:], lines[1][1:]))
            for key, name in (("RcvbufErrors", "receive_buffer_errors"), ("InErrors", "receive_errors")):
                if row.get(key, "").isdigit():
                    out[name] = int(row[key])
    for key, name in (("rmem_max", "rmem_max_kb"), ("rmem_default", "rmem_default_kb")):
        value = _read(os.path.join(proc_root, "sys", "net", "core", key))
        if value and value.isdigit():
            out[name] = int(value) // 1024
    return out


def cpu_info(root="/sys/fs/cgroup"):
    logical = os.cpu_count() or 1
    affinity = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    quota = cgroup_cpu_limit(root)
    candidates = [logical] + [v for v in (affinity, quota) if v]
    return {"logical": logical, "affinity": affinity,
            "container_quota": round(quota, 2) if quota else None,
            "effective": round(min(candidates), 2)}


def database_info(db_config=None):
    cfg = db_config or {}
    backend = cfg.get("backend", "sqlite")
    info = {"backend": backend}
    if backend == "postgres":
        host = str((cfg.get("postgres") or {}).get("host") or "")
        info["host"] = host or "local socket"
        info["same_host"] = host in ("", "localhost", "127.0.0.1", "::1") or host.startswith("/")
    else:
        path = (cfg.get("sqlite") or {}).get("path", "siem.db")
        info["path"] = path
        try:
            usage = shutil.disk_usage(os.path.dirname(os.path.abspath(path)) or ".")
            info["disk_free_mb"] = usage.free // 2**20
        except OSError:
            info["disk_free_mb"] = None
        info["same_host"] = True
    return info


def scan(db_config=None, cgroup_root="/sys/fs/cgroup"):
    total, available = memory_info()
    load = os.getloadavg() if hasattr(os, "getloadavg") else None
    return {
        "host": platform.node(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": platform.python_version(),
        "cpu": cpu_info(cgroup_root),
        "memory": {"total_mb": total, "available_mb": available,
                   "container_limit_mb": cgroup_memory_limit_mb(cgroup_root)},
        "load_average": [round(v, 2) for v in load] if load else None,
        "udp": udp_info(),
        "database": database_info(db_config),
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ---------------------------------------------------------------- measuring

_PROBE = r"""
import os, sys
sys.path.insert(0, os.getcwd())
import listener, rules, normalize, threatintel, forwarder, db, detection  # noqa: F401  ingest code
rss = None
status = "/proc/self/status"
if os.path.exists(status):
    for line in open(status):
        if line.startswith("VmRSS:"):
            rss = int(line.split()[1]) / 1024
if rss is None and sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
    class PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
    if ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        rss = pmc.WorkingSetSize / 2**20
if rss is None:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss = peak / 2**20 if sys.platform == "darwin" else peak / 1024
print(round(rss, 1))
"""


def measure_process_memory(timeout=60):
    """Resident MB of a fresh Python process with the ingest code imported,
    or None if it cannot be measured. A running ingest process also holds
    database buffers and caches; recommend() adds headroom for that."""
    try:
        out = subprocess.run([sys.executable, "-c", _PROBE], cwd=HERE, capture_output=True,
                             text=True, timeout=timeout)
        return float(out.stdout.strip().splitlines()[-1]) if out.returncode == 0 else None
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


_SAMPLES = [
    "<38>Nov  5 09:00:00 bastion sshd[1]: Failed password for root from 203.0.113.{n} port 22 ssh2",
    "<134>Nov  5 09:00:00 fw01 kernel: action=deny src=198.51.100.{n} dst=10.0.0.5 proto=tcp dport=445",
    "<30>Nov  5 09:00:00 app01 nginx: GET /index.html 200 user=alice src=192.0.2.{n}",
    '<14>Nov  5 09:00:00 WEB01 {{"EventID":4688,"Channel":"Security","SourceName":"Microsoft-Windows-Security-Auditing",'
    '"Hostname":"WEB01","NewProcessName":"C:\\\\Windows\\\\System32\\\\cmd.exe","ParentProcessName":"C:\\\\Tomcat\\\\tomcat.exe",'
    '"CommandLine":"cmd.exe /c whoami","SubjectUserName":"svc{n}","EventTime":"2026-11-05T09:00:00+08:00"}}',
]


def benchmark(seconds=2.0):
    """Events/second for parse + field extraction + rule evaluation in one
    Python process, without database writes (an in-memory alert sink)."""
    import threading
    import listener
    import normalize
    import rules

    class _Sink:                               # no .conn: the engine keeps default rules
        lock = threading.RLock()

        def insert_alert(self, **_kw):
            return None

    engine = rules.RuleEngine(_Sink())
    deadline = time.perf_counter() + max(0.2, float(seconds))
    started, n = time.perf_counter(), 0
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):   # rule hits print alerts
        while time.perf_counter() < deadline:
            raw = _SAMPLES[n % len(_SAMPLES)].format(n=n % 250)
            event = listener.parse_syslog(raw, "10.0.0.7")
            fields = normalize.extract_fields(event.get("message"), [])
            engine.process(n, event, fields=fields)
            n += 1
    elapsed = time.perf_counter() - started
    return {"events": n, "seconds": round(elapsed, 2), "events_per_second": int(n / elapsed) if elapsed else 0,
            "note": "CPU work only (parse, fields, rules); database writes are not included."}


# ---------------------------------------------------------------- deciding

def _clamp(value, key):
    low, high = LIMITS[key]
    return max(low, min(high, int(value)))


def recommend(scan_result, process_mb=None, benchmark_eps=None, ioc_count=0):
    """Recommended ingest processes/threads/queue size with the reasons.

    Rules, in order:
    * SQLite accepts one writer at a time: extra processes only wait on its
      lock, so SQLite gets one process with a few threads.
    * CPU: keep one core for the web console/OS, and a quarter of the cores
      for PostgreSQL when it runs on this machine. Several ingest processes
      also need the receiving process, which parses and routes every message.
    * Memory: keep OS headroom and room for the dashboard (and a quarter of
      memory for a local PostgreSQL); each ingest process needs its own
      Python runtime plus its queue.
    The smaller of the CPU and memory limits wins, capped at 16 processes.
    Every process keeps its own copy of the enabled threat indicators.
    """
    cpu = scan_result["cpu"]
    mem = scan_result["memory"]
    db = scan_result["database"]
    reasons, warnings = [], []
    effective = float(cpu.get("effective") or 1)
    cores = max(1, int(effective))
    # A fresh import is the floor; buffers, caches and the indicator index grow at runtime.
    per_process_mb = max(MIN_PROCESS_MB, float(process_mb or DEFAULT_PROCESS_MB) * 1.5) \
        + (ioc_count or 0) * IOC_KB / 1024
    measured = process_mb is not None

    available = mem.get("available_mb")
    if mem.get("container_limit_mb"):
        available = min(available, mem["container_limit_mb"]) if available else mem["container_limit_mb"]
    local_pg = db.get("backend") == "postgres" and db.get("same_host")

    reserve_cpu = (1 if cores >= 2 else 0) + (max(1, cores // 4) if local_pg else 0)
    cpu_slots = max(1, cores - reserve_cpu)
    cpu_processes = cpu_slots - 1 if cpu_slots >= 3 else 1
    reasons.append(f"CPU: {effective:g} usable core(s)"
                   + (f" (container quota {cpu['container_quota']:g})" if cpu.get("container_quota") else "")
                   + f"; {reserve_cpu} kept for the web console/OS"
                   + (" and the local PostgreSQL server" if local_pg else "")
                   + (", 1 for the receiving process" if cpu_slots >= 3 else "")
                   + f" → up to {cpu_processes} ingest process(es).")

    def queue_for(count):
        """Messages per process queue: at most 10% of free memory overall."""
        if available is None or available <= OS_HEADROOM_MB:
            return 1000
        budget_items = (available - OS_HEADROOM_MB) * 0.10 * 1024 / QUEUE_ITEM_KB
        return _clamp(min(50000, max(1000, budget_items / max(1, count))), "queue_size")

    if available is None:
        mem_processes = cpu_processes
        warnings.append("Available memory could not be read; the memory limit was not applied.")
    else:
        reserve_mb = OS_HEADROOM_MB + DASHBOARD_MB + (int((mem.get("total_mb") or available) * 0.25) if local_pg else 0)
        queue_mb = queue_for(cpu_processes) * QUEUE_ITEM_KB / 1024
        budget = available - reserve_mb
        mem_processes = int(budget // (per_process_mb + queue_mb)) if budget > 0 else 0
        reasons.append(f"Memory: {available} MB available, {reserve_mb} MB kept for the OS/web console"
                       + (" and PostgreSQL" if local_pg else "")
                       + f"; about {per_process_mb + queue_mb:.0f} MB per ingest process"
                       + (f" (measured {process_mb:.0f} MB at start" if measured else " (estimate")
                       + (f", {ioc_count:,} threat indicators" if ioc_count else "") + ")"
                       + f" → up to {max(mem_processes, 0)} process(es).")
        if mem_processes < 1:
            warnings.append("Very little free memory: run one ingest process and keep queues small.")

    processes = max(1, min(cpu_processes, mem_processes if available is not None else cpu_processes, MAX_PROCESSES))
    if db.get("backend") != "postgres":
        if processes > 1:
            reasons.append(f"SQLite: one ingest process (this machine could run {processes}); SQLite accepts "
                           "one writer at a time, so more processes would only wait. Use PostgreSQL to scale out.")
        processes = 1

    if processes == 1:
        threads = 4 if db.get("backend") == "postgres" else 2
        reasons.append(f"One process with {threads} worker threads: threads overlap database waits; "
                       "detection itself runs one event at a time.")
    else:
        threads = 1
        reasons.append(f"{processes} ingest processes, each handling its share of messages one at a time; "
                       "messages are routed by the address repeated-activity rules count, so counts stay correct.")

    queue_size = queue_for(processes)
    reasons.append(f"Queue: {queue_size} messages per process (about {queue_size * QUEUE_ITEM_KB // 1024} MB) "
                   "absorbs bursts; UDP messages beyond it are dropped and counted, TCP senders are slowed.")

    udp = scan_result.get("udp") or {}
    if udp.get("rmem_max_kb") is not None and udp["rmem_max_kb"] < UDP_BUFFER_KB:
        warnings.append(f"The kernel limits UDP receive buffers to {udp['rmem_max_kb']} KB, so bursts of a few hundred "
                        f"messages can be lost before mini-SIEM reads them. Raise it: sysctl -w net.core.rmem_max="
                        f"{UDP_BUFFER_KB * 1024} (and persist it in /etc/sysctl.d).")
    if udp.get("receive_buffer_errors"):
        warnings.append(f"The kernel has dropped {udp['receive_buffer_errors']:,} UDP datagrams since boot because a "
                        "receive buffer was full (all UDP services on this host). Increasing processes does not "
                        "help this; a larger buffer and a faster queue do.")

    load = scan_result.get("load_average")
    if load and load[0] > 0.7 * effective:
        warnings.append(f"The machine is already busy (load {load[0]} on {effective:g} cores); "
                        "the recommendation may be optimistic.")
    if db.get("backend") == "sqlite" and db.get("disk_free_mb") is not None and db["disk_free_mb"] < 2048:
        warnings.append(f"Only {db['disk_free_mb']} MB free next to the SQLite database.")

    out = {"processes": processes, "threads": threads, "queue_size": queue_size,
           "mode": "processes" if processes > 1 else "threads",
           "limits": {"cpu": cpu_processes, "memory": None if available is None else max(mem_processes, 0)},
           "reasons": reasons, "warnings": warnings}
    if benchmark_eps:
        out["estimated_events_per_second"] = int(benchmark_eps * processes)
        reasons.append(f"CPU ceiling ≈ {out['estimated_events_per_second']:,} events/s "
                       f"({int(benchmark_eps):,} per process, before database write time).")
    return out


# ---------------------------------------------------------------- resolving

def validate(values):
    """Check an "ingest" settings dict. Returns (clean, error)."""
    clean = {}
    if not isinstance(values, dict):
        return None, "Ingest settings must be an object"
    for key in ("processes", "threads", "queue_size", "udp_buffer_kb"):
        if key not in values or values[key] in (None, ""):
            continue
        value = values[key]
        if key == "processes" and str(value).lower() == "auto":
            clean[key] = "auto"
            continue
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None, f"{key} must be a whole number" + (" or auto" if key == "processes" else "")
        low, high = LIMITS[key]
        if not low <= number <= high:
            return None, f"{key} must be between {low} and {high}"
        clean[key] = number
    return clean, None


def ingest_settings(db_config=None, overrides=None, scan_result=None):
    """What the listener will run: command-line overrides, then db-config.json
    "ingest", then defaults. "auto" (processes) uses this machine's scan."""
    configured, error = validate((db_config or {}).get("ingest") or {})
    warnings = [f"Ignored invalid ingest settings in db-config.json: {error}"] if error else []
    configured = configured or {}
    cli, cli_error = validate({k: v for k, v in (overrides or {}).items() if v is not None})
    if cli_error:
        raise ValueError(cli_error)
    merged = {**DEFAULTS, **configured, **cli}
    source = {k: ("command line" if k in cli else "db-config.json" if k in configured else "default") for k in DEFAULTS}
    recommendation = None
    if merged["processes"] == "auto":
        recommendation = recommend(scan_result or scan(db_config))
        merged["processes"] = recommendation["processes"]
        source["processes"] = "auto (machine scan)"
        for key in ("threads", "queue_size"):
            if source[key] == "default":
                merged[key] = recommendation[key]
                source[key] = "auto (machine scan)"
    if merged["processes"] > 1 and (db_config or {}).get("backend", "sqlite") != "postgres":
        warnings.append("Several ingest processes with SQLite: they share one database writer and mostly wait. "
                        "Use PostgreSQL, or one process.")
    return {"processes": merged["processes"], "threads": merged["threads"], "queue_size": merged["queue_size"],
            "udp_buffer_kb": merged["udp_buffer_kb"],
            "mode": "processes" if merged["processes"] > 1 else "threads",
            "source": source, "warnings": warnings, "recommendation": recommendation}
