"""Job leases, queued/multi-process ingest, capacity scan and their UI."""
import json
import os
import threading
import time
from pathlib import Path

import pytest

import capacity
import db
import leases
from session_helpers import sign_in

ROOT = Path(__file__).resolve().parents[1]
H = {"X-CSRF-Token": "t"}


@pytest.fixture
def cfg(tmp_path):
    config = db.config_from_path(str(tmp_path / "w.db"))
    db.initialize(config)
    return config


def keeper(cfg, owner, clock):
    return leases.LeaseKeeper(lambda: db.connect(cfg), owner=owner, clock=lambda: clock[0])


# ---------------------------------------------------------------- leases

def test_lease_has_one_holder_and_fails_over_after_expiry(cfg):
    clock = [1000.0]
    a, b = keeper(cfg, "A", clock), keeper(cfg, "B", clock)
    assert a.hold("ticket-worker", 60) and not b.hold("ticket-worker", 60)
    clock[0] += 30
    assert a.hold("ticket-worker", 60) and not b.hold("ticket-worker", 60)    # renewal extends
    clock[0] += 61                                                            # A stopped renewing
    assert b.hold("ticket-worker", 60) and not a.hold("ticket-worker", 60)
    assert b.holds("ticket-worker") and not a.holds("ticket-worker")
    b.release("ticket-worker")
    assert a.hold("ticket-worker", 60)
    conn = db.connect(cfg)
    status = leases.lease_status(conn, now=clock[0])
    conn.close()
    assert status == [{"job": "ticket-worker", "owner": "A", "state": "held", "expires_in_seconds": 60,
                       "held_since": clock[0], "renewed_at": clock[0]}]


def test_missing_lease_table_keeps_single_process_behaviour(cfg, capsys):
    conn = db.connect(cfg)
    conn.execute("DROP TABLE worker_leases"); conn.commit(); conn.close()
    k = keeper(cfg, "A", [1.0])
    assert k.hold("ai-triage", 60) and k.unavailable and k.holds("ai-triage")
    assert "worker_leases table missing" in capsys.readouterr().out


def test_workers_skip_cycles_without_the_lease():
    import ai_worker
    import workers
    for make in (lambda lease: workers.TicketWorker(None, None, lease=lease),
                 lambda lease: workers.FeedRefresher(None, lease=lease),
                 lambda lease: ai_worker.TriageWorker(None, None, lease=lease)):
        ran = []
        w = make(lambda: False)
        w.run_once = lambda: ran.append(1)
        w._cycle()
        w.lease = lambda: True
        w._cycle()
        assert ran == [1]
    sched = workers.ReportScheduler(None, lambda: "weekly", lease=lambda: False)
    sched.run_if_due = lambda: pytest.fail("ran without the lease")
    assert sched._cycle() is None


def test_two_processes_never_send_the_same_tickets(cfg):
    import workers
    clock = [1000.0]
    sent = []
    pair = []
    for owner in ("A", "B"):
        w = workers.TicketWorker(None, None, lease=keeper(cfg, owner, clock).binding("ticket-worker", 60))
        w.run_once = (lambda o: lambda: sent.append(o))(owner)
        pair.append(w)
    for _ in range(3):
        for w in pair:
            w._cycle()
    assert sent == ["A", "A", "A"]


def test_cloud_connections_are_shared_between_processes(cfg):
    import api_poller
    clock = [1000.0]
    managers = [api_poller.PollerManager(lambda: db.connect(cfg), None, None, lease_keeper=keeper(cfg, o, clock))
                for o in ("A", "B")]
    polled = []
    for rid in (1, 2):
        for name, mgr in zip("AB", managers):
            t = api_poller._PollerThread(rid, mgr)
            t._poll_once = (lambda n, r: lambda row: polled.append((n, r)) or ([], None))(name, rid)
            mgr.record_success = lambda *a: None
            t._cycle({"id": rid}, 60)
    assert sorted(polled) == [("A", 1), ("A", 2)]           # one poller per connection
    clock[0] += 200                                          # A stops; B takes over
    t = api_poller._PollerThread(1, managers[1])
    t._poll_once = lambda row: polled.append(("B", 1)) or ([], None)
    managers[1].record_success = lambda *a: None
    assert t._cycle({"id": 1}, 60) and polled[-1] == ("B", 1)


# ---------------------------------------------------------------- queued ingest (one process)

def test_pipeline_keeps_each_senders_order_across_workers():
    from listener import IngestPipeline
    seen = {}
    lock = threading.Lock()

    def process(raw, source, received_at):
        time.sleep(0.001)
        with lock:
            seen.setdefault(source, []).append(int(raw))
    p = IngestPipeline(None, worker_count=4, queue_size=4000, process=process)
    for i in range(400):
        assert p.submit(str(i), f"10.0.0.{i % 7}")
    p.stop(drain=True, timeout=10)
    assert sum(len(v) for v in seen.values()) == 400
    assert all(v == sorted(v) for v in seen.values())
    stats = p.stats()
    assert stats["processed"] == 400 and stats["workers"] == 4 and stats["queue_capacity"] == 4000


def test_full_queue_drops_udp_but_slows_tcp():
    from listener import IngestPipeline
    gate = threading.Event()
    p = IngestPipeline(None, worker_count=1, queue_size=1, process=lambda *a: gate.wait(5), tcp_wait=0.3)
    assert p.submit("a", "1.1.1.1") and p.submit("b", "1.1.1.1", transport="tcp")
    time.sleep(0.05)
    assert not p.submit("c", "1.1.1.1", transport="udp")
    started = time.monotonic()
    assert not p.submit("d", "1.1.1.1", transport="tcp")
    assert time.monotonic() - started >= 0.25                # TCP waited before giving up
    stats = p.stats()
    assert (stats["dropped"], stats["dropped_udp"], stats["dropped_tcp"]) == (2, 1, 1)
    gate.set(); p.stop(drain=True, timeout=5)


# ---------------------------------------------------------------- multi-process ingest

def test_route_key_matches_the_repeated_activity_rule_key():
    import ingest_workers
    a = {"message": "Failed password for root from 203.0.113.9 port 22", "source_ip": "10.0.0.1"}
    b = {"message": "Failed password for admin from 203.0.113.9 port 22", "source_ip": "10.0.0.2"}
    assert ingest_workers.route_key(a) == ingest_workers.route_key(b) == "203.0.113.9"
    assert ingest_workers.route_key({"message": "no address here", "source_ip": "10.0.0.3"}) == "10.0.0.3"


@pytest.mark.timeout(120) if hasattr(pytest.mark, "timeout") else (lambda f: f)
def test_processes_count_one_attacker_across_senders_and_restart(cfg):
    import ingest_workers
    p = ingest_workers.ProcessIngest(cfg, 2, 200)
    try:
        deadline = time.time() + 60
        while time.time() < deadline and p.stats()["workers_alive"] < 2:
            time.sleep(0.2)
        time.sleep(2)                                        # children open their databases
        for i in range(12):                                  # 4 devices report one attacker
            assert p.submit(f"<38>Nov  5 09:00:{i:02d} fw{i % 4} sshd[1]: Failed password for root "
                            f"from 203.0.113.99 port 22", f"10.0.0.{i % 4 + 1}")
        for i in range(6):
            assert p.submit(f"<30>Nov  5 09:00:00 app nginx: GET /{i} 200", "10.0.0.9")
        deadline = time.time() + 30
        while time.time() < deadline and p.stats()["processed"] < 18:
            time.sleep(0.2)
        assert p.stats()["processed"] == 18 and p.stats()["failed"] == 0
        p.procs[0].kill(); p.procs[0].join(5)
        assert p.supervise() == 1 and p.stats()["restarts"] == 1
        failed_before = p.stats()["failed"]
        for i in range(20):                                  # spread over both children, incl. the new one
            assert p.submit(f"<30>Nov  5 09:01:00 app nginx: GET /after 200 src=198.51.100.{i}", "10.0.0.9")
        deadline = time.time() + 60
        while time.time() < deadline and p.stats()["processed"] < 38:
            time.sleep(0.2)
        assert p.stats()["processed"] == 38 and p.stats()["failed"] == failed_before
    finally:
        p.stop(timeout=15)
    conn = db.connect(cfg)
    logs = conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
    alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE rule_name='ssh_bruteforce'").fetchone()["n"]
    conn.close()
    assert logs == 38 and alerts == 2                         # 12 hits / threshold 5, as with one process


# ---------------------------------------------------------------- capacity scan

def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_cgroup_and_kernel_readers(tmp_path):
    _write(tmp_path / "v2", "cpu.max", "200000 100000")
    _write(tmp_path / "v2", "memory.max", str(2 * 1024**3))
    assert capacity.cgroup_cpu_limit(str(tmp_path / "v2")) == 2.0
    assert capacity.cgroup_memory_limit_mb(str(tmp_path / "v2")) == 2048
    _write(tmp_path / "unl", "cpu.max", "max 100000")
    _write(tmp_path / "unl", "memory.max", "max")
    assert capacity.cgroup_cpu_limit(str(tmp_path / "unl")) is None
    assert capacity.cgroup_memory_limit_mb(str(tmp_path / "unl")) is None
    _write(tmp_path / "v1", "cpu/cpu.cfs_quota_us", "150000")
    _write(tmp_path / "v1", "cpu/cpu.cfs_period_us", "100000")
    _write(tmp_path / "v1", "memory/memory.limit_in_bytes", str(1 << 62))
    assert capacity.cgroup_cpu_limit(str(tmp_path / "v1")) == 1.5
    assert capacity.cgroup_memory_limit_mb(str(tmp_path / "v1")) is None   # v1 "unlimited"
    _write(tmp_path / "proc", "net/snmp", "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors\nUdp: 10 0 7 3 7\n")
    _write(tmp_path / "proc", "sys/net/core/rmem_max", "212992")
    udp = capacity.udp_info(str(tmp_path / "proc"))
    assert udp["receive_buffer_errors"] == 7 and udp["rmem_max_kb"] == 208


def _scan(cores, avail_mb, backend="postgres", same_host=False, quota=None, rmem_kb=8192, drops=0):
    return {"cpu": {"logical": cores, "effective": quota or cores, "container_quota": quota},
            "memory": {"total_mb": avail_mb, "available_mb": avail_mb, "container_limit_mb": None},
            "load_average": [0.1, 0.1, 0.1], "udp": {"rmem_max_kb": rmem_kb, "receive_buffer_errors": drops},
            "database": {"backend": backend, "same_host": same_host, "disk_free_mb": 50000}}


@pytest.mark.parametrize("scan,processes", [
    (_scan(8, 16000), 6),                                   # 1 core web/OS, 1 receiving process
    (_scan(8, 16000, same_host=True), 4),                   # local PostgreSQL keeps 2 more cores
    (_scan(8, 16000, quota=2.0), 1),                        # container quota wins over cores
    (_scan(32, 16000), 16),                                 # hard cap
    (_scan(8, 900), 1),                                     # memory wins
    (_scan(8, 16000, backend="sqlite"), 1),                 # one SQLite writer
])
def test_recommendation_limits(scan, processes):
    rec = capacity.recommend(scan)
    assert rec["processes"] == processes and rec["mode"] == ("processes" if processes > 1 else "threads")
    assert rec["reasons"] and 100 <= rec["queue_size"] <= 50000


def test_recommendation_explains_memory_indicators_and_kernel_buffers():
    lean = capacity.recommend(_scan(8, 2000), process_mb=40)
    heavy = capacity.recommend(_scan(8, 2000), process_mb=40, ioc_count=2_000_000)
    assert heavy["processes"] < lean["processes"]            # each process holds the indicator index
    assert any("threat indicators" in r for r in heavy["reasons"])
    rec = capacity.recommend(_scan(4, 8000, rmem_kb=208, drops=55), benchmark_eps=20000)
    assert any("net.core.rmem_max" in w for w in rec["warnings"]) and any("dropped 55" in w for w in rec["warnings"])
    assert rec["estimated_events_per_second"] == 20000 * rec["processes"]


def test_ingest_settings_resolution():
    sqlite = {"backend": "sqlite"}
    assert capacity.ingest_settings(sqlite)["mode"] == "threads"
    auto = capacity.ingest_settings({"backend": "postgres", "ingest": {"processes": "auto"}},
                                    scan_result=_scan(8, 16000))
    assert auto["processes"] == 6 and auto["source"]["processes"] == "auto (machine scan)"
    cli = capacity.ingest_settings({"backend": "postgres", "ingest": {"processes": 3}}, {"processes": "2"})
    assert cli["processes"] == 2 and cli["source"]["processes"] == "command line"
    warn = capacity.ingest_settings({"backend": "sqlite", "ingest": {"processes": 4}})
    assert warn["processes"] == 4 and "SQLite" in warn["warnings"][0]
    bad = capacity.ingest_settings({"ingest": {"processes": 99}})
    assert bad["processes"] == 1 and "Ignored invalid" in bad["warnings"][0]
    with pytest.raises(ValueError):
        capacity.ingest_settings({}, {"threads": "0"})


def test_measurements_run():
    assert capacity.benchmark(0.3)["events_per_second"] > 0
    mb = capacity.measure_process_memory()
    assert mb is None or 5 < mb < 2000


# ---------------------------------------------------------------- schema

def test_fresh_database_has_forwarder_columns_and_repairs_old_ones(cfg):
    conn = db.connect(cfg)
    cols = [r[1] for r in conn.raw.execute("PRAGMA table_info(forwarders)")]
    assert "origin_mode" in cols and "tcp_framing" in cols
    conn.raw.execute("ALTER TABLE forwarders DROP COLUMN origin_mode"); conn.raw.commit(); conn.close()
    db.initialize(cfg)
    conn = db.connect(cfg)
    assert "origin_mode" in [r[1] for r in conn.raw.execute("PRAGMA table_info(forwarders)")]
    assert conn.execute("SELECT COUNT(*) AS n FROM worker_leases").fetchone()["n"] == 0
    conn.close()


def test_listener_starts_on_a_fresh_database(cfg):
    import listener
    from forwarder import ForwarderManager
    ForwarderManager(listener.Storage(db_config=cfg), listen_port=514)   # raised "no such column" before


# ---------------------------------------------------------------- web console

@pytest.fixture
def app(tmp_path, monkeypatch):
    import dashboard
    config = db.config_from_path(str(tmp_path / "web.db"))
    monkeypatch.setattr(dashboard, "DB_CONFIG", config)
    dashboard.init_auth(None)
    db.initialize(config)
    path = tmp_path / "db-config.json"
    path.write_text(json.dumps({"backend": "sqlite", "ingest": {"udp_buffer_kb": 8192}}))
    monkeypatch.setattr(dashboard, "_config_file_path", lambda: str(path))
    return dashboard, config, path


def client(dashboard, role="admin"):
    c = dashboard.app.test_client()
    sign_in(dashboard, c, "alice", role)
    return c


def test_capacity_api_is_admin_only_and_complete(app):
    dashboard, config, _ = app
    d = client(dashboard).get("/api/capacity").get_json()
    assert d["recommendation"]["processes"] == 1 and d["scan"]["cpu"]["effective"] >= 1
    assert d["configured"]["udp_buffer_kb"] == 8192 and d["jobs"] == [] and d["this_process"]
    for role in ("analyst", "viewer"):
        assert client(dashboard, role).get("/api/capacity").status_code == 403
        assert client(dashboard, role).post("/api/capacity/benchmark", headers=H).status_code == 403


def test_ingest_settings_are_validated_saved_and_audited(app):
    dashboard, config, path = app
    c = client(dashboard)
    assert c.post("/api/ingest-settings", json={"processes": 0}, headers=H).status_code == 400
    assert c.post("/api/ingest-settings", json={"threads": 2}, headers=H).status_code == 400
    r = c.post("/api/ingest-settings", json={"processes": "auto", "threads": "4", "queue_size": 20000}, headers=H)
    assert r.status_code == 200 and r.get_json()["restart_required"]
    saved = json.loads(path.read_text())
    assert saved["ingest"] == {"processes": "auto", "threads": 4, "queue_size": 20000, "udp_buffer_kb": 8192}
    assert saved["backend"] == "sqlite"                                 # rest of the file untouched
    conn = db.connect(config)
    detail = conn.execute("SELECT detail FROM audit_log WHERE action='ingest_settings_changed'").fetchone()["detail"]
    conn.close()
    assert "processes=auto" in detail
    assert client(dashboard, "analyst").post("/api/ingest-settings", json={"processes": 2}, headers=H).status_code == 403


def test_listener_health_reports_the_pipeline(cfg):
    import listener
    from runtime_health import listener_snapshot_from_db
    reporter = listener.ListenerRuntimeReporter(cfg)
    reporter.set_pipeline(listener.IngestPipeline(None, worker_count=3, queue_size=300, process=lambda *a: None))
    reporter._write()
    conn = db.connect(cfg)
    snap = listener_snapshot_from_db(conn)
    conn.close()
    assert snap["worker"] == "THREADS x3" and snap["ingest_workers"] == 3 and snap["queue_capacity"] == 300


def test_ui_contracts():
    health = (ROOT / "templates" / "health.html").read_text(encoding="utf-8")
    setup = (ROOT / "templates" / "setup.html").read_text(encoding="utf-8")
    assert "/api/capacity/benchmark" in health and "MS.background(loadCapacity)" in health
    assert "Background jobs" in health and "Kernel UDP drops since boot" in health
    assert 'id="ingProcesses"' in setup and "/api/ingest-settings" in setup and "Use recommended" in setup
