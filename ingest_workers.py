"""Multi-process ingest: one receiving process, N storing/detecting processes.

The listener process receives every message, parses it and routes it to one
child process by the address repeated-activity rules count (the first IP in
the message, else the sender; see rules.ThresholdRule). All messages about
one attacker therefore reach the same child, so "5 failed logins in 60s"
counts stay correct even when several devices report the same attacker.

Each child has its own database connection, detection engine, indicator
matcher, field indexer and forwarders. Expected-log-delivery monitoring runs
in every child and merges into shared database state (detection_runtime).

Children use the "spawn" start method on every platform: the listener
already runs receive threads, and forking a threaded process can copy held
locks into the child. A child that exits unexpectedly is restarted; the
message it was handling may be lost and is counted as failed.
"""
import multiprocessing as mp
import os
import queue
import signal
import threading
import time
import zlib


def route_key(event):
    """The key repeated-activity rules count by (rules.ThresholdRule)."""
    from rules import extract_ip
    return extract_ip(event.get("message") or "") or event.get("source_ip") or "unknown"


def _child_main(index, db_config, work, counters, listen_port):
    # The receiving process owns shutdown: it drains, then sends a sentinel.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    import listener
    from forwarder import ForwarderManager
    from normalize import FieldIndexer
    from rules import RuleEngine
    from threatintel import IOCMatcher

    storage = listener.Storage(db_config=db_config)
    engine = RuleEngine(storage)
    engine.start_monitor()
    forwarders = ForwarderManager(storage, listen_port=listen_port)
    ioc = IOCMatcher(storage)
    fields = FieldIndexer(storage)
    parent = mp.parent_process()
    slot = index * 2
    print(f"[ingest-{index}] ready (pid {os.getpid()})")
    while True:
        try:
            event = work.get(timeout=1.0)
        except queue.Empty:
            if parent is not None and not parent.is_alive():
                break                      # receiving process is gone
            continue
        if event is None:
            break
        try:
            extracted = fields.extract(event)
            log_id = storage.insert_log(event, fields=extracted)
            try:
                fields._maybe_capture_unidentified(log_id, event, len(extracted))
            except Exception:  # noqa: BLE001 - diagnostics only
                pass
            engine.process(log_id, event, fields=extracted)
            ioc.process(log_id, event)
            forwarders.forward(event)
            with counters.get_lock():
                counters[slot] += 1
            print(f"[{event['received_at']}] {event.get('source_ip')} [{event.get('severity') or '-'}] "
                  f"{(event.get('message') or '')[:120]}")
        except Exception as exc:  # noqa: BLE001 - one bad event must not stop the child
            with counters.get_lock():
                counters[slot + 1] += 1
            print(f"[ingest-{index}] event failed: {type(exc).__name__}: {exc}")
    try:
        storage.conn.commit()
    except Exception:  # noqa: BLE001
        pass


class ProcessIngest:
    """Route parsed events to ``processes`` child processes.

    ``submit`` has the same contract as listener.IngestPipeline.submit: UDP
    never waits (a full child queue drops and counts), TCP waits up to
    ``tcp_wait`` seconds to slow the sender instead of losing data.
    """

    def __init__(self, db_config, processes, queue_size, listen_port=514, tcp_wait=2.0,
                 parse=None, start=True):
        import listener
        self.db_config = db_config
        self.count = max(2, int(processes))
        self.queue_size = max(1, int(queue_size))
        self.listen_port = listen_port
        self.tcp_wait = max(0.0, float(tcp_wait))
        self.parse = parse or listener.parse_syslog
        self._ctx = mp.get_context("spawn")
        self.queues = [self._ctx.Queue(maxsize=self.queue_size) for _ in range(self.count)]
        self.counters = self._ctx.Array("q", 2 * self.count)   # processed, failed per child
        self.procs = [None] * self.count
        self.restarts = 0
        self._stopping = False
        self._lock = threading.Lock()
        self._stats = {"dropped": 0, "dropped_udp": 0, "dropped_tcp": 0, "parse_failed": 0}
        if start:
            for i in range(self.count):
                self._start(i)

    def _start(self, index):
        proc = self._ctx.Process(target=_child_main, name=f"mini-siem-ingest-{index}",
                                 args=(index, self.db_config, self.queues[index], self.counters, self.listen_port),
                                 daemon=True)
        proc.start()
        self.procs[index] = proc

    def submit(self, raw, source_ip, transport="udp", received_at=None, key=None):
        try:
            event = self.parse(raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw, source_ip)
        except Exception:  # noqa: BLE001
            with self._lock:
                self._stats["parse_failed"] += 1
            return False
        if received_at:
            event["received_at"] = received_at
        index = zlib.crc32(route_key(event).encode("utf-8")) % self.count
        try:
            if transport == "tcp" and self.tcp_wait:
                self.queues[index].put(event, timeout=self.tcp_wait)
            else:
                self.queues[index].put_nowait(event)
            return True
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1
                self._stats["dropped_tcp" if transport == "tcp" else "dropped_udp"] += 1
            return False

    def supervise(self):
        """Restart any child that exited unexpectedly. Call periodically."""
        if self._stopping:
            return 0
        restarted = 0
        for i, proc in enumerate(self.procs):
            if proc is not None and not proc.is_alive():
                print(f"[ingest] process {i} exited (code {proc.exitcode}); restarting")
                # A process that dies inside Queue.get can leave the queue's
                # reader lock held, which would block its replacement forever.
                # Start the replacement on a fresh queue; messages still
                # waiting in the old one are lost and counted as failed.
                old = self.queues[i]
                try:
                    lost = old.qsize()
                except NotImplementedError:
                    lost = 0
                old.cancel_join_thread()
                old.close()
                self.queues[i] = self._ctx.Queue(maxsize=self.queue_size)
                with self.counters.get_lock():
                    self.counters[i * 2 + 1] += 1 + lost  # the event it held, if any, plus the backlog
                self._start(i)
                self.restarts += 1
                restarted += 1
        return restarted

    def stats(self):
        with self._lock:
            out = dict(self._stats)
        with self.counters.get_lock():
            values = list(self.counters)
        depth = 0
        for q in self.queues:
            try:
                depth += q.qsize()
            except NotImplementedError:   # macOS: qsize is unavailable
                depth = None
                break
        out.update(mode="processes", workers=self.count,
                   workers_alive=sum(1 for p in self.procs if p is not None and p.is_alive()),
                   processed=sum(values[0::2]), failed=sum(values[1::2]) + out["parse_failed"],
                   queue_depth=depth, queue_capacity=self.queue_size * self.count, restarts=self.restarts)
        return out

    def stop(self, drain=True, timeout=10.0):
        """Send each child a sentinel after its queued events, then wait."""
        self._stopping = True
        deadline = time.monotonic() + max(0.5, float(timeout))
        for q in self.queues:
            try:
                q.put(None, timeout=max(0.1, deadline - time.monotonic()) if drain else 0.1)
            except queue.Full:
                pass
        for proc in self.procs:
            if proc is not None:
                proc.join(timeout=max(0.1, deadline - time.monotonic()))
        for proc in self.procs:
            if proc is not None and proc.is_alive():
                proc.kill()        # children ignore SIGTERM (the receiver owns shutdown)
                proc.join(timeout=2)
        # The children are gone: anything still buffered has no reader, and
        # waiting to flush it would hang interpreter exit.
        for q in self.queues:
            q.cancel_join_thread()
            q.close()
