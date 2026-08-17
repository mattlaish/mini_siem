#!/usr/bin/env python3
"""
mini-SIEM — single entry point
===============================
Runs the syslog listener AND the web dashboard together in one process,
so one command starts everything:

    sudo python3 siem.py

Options (all optional):
    --port 514              syslog listen port
    --protocol both         udp | tcp | both
    --host 0.0.0.0          syslog bind address
    --db siem.db            SQLite database path
    --dashboard-host 127.0.0.1
    --dashboard-port 8080
    --no-dashboard          run the listener only

The individual scripts (listener.py / dashboard.py) still work on their
own if you ever want to run them on separate machines.

Note: running this combined process with sudo (for port 514) means the
dashboard also runs as root. Keep --dashboard-host on 127.0.0.1 and use
an SSH tunnel for remote access, or use the setcap / port-redirect
options in the README to avoid root entirely.
"""

import argparse
import sys
import threading
import time

from listener import Storage, parse_syslog, tcp_listener, udp_listener
from rules import RuleEngine
from forwarder import ForwarderManager
from threatintel import IOCMatcher
from normalize import FieldIndexer
import dashboard
import db as dbmod


def main():
    ap = argparse.ArgumentParser(description="mini-SIEM (listener + dashboard)")
    ap.add_argument("--host", default="0.0.0.0", help="syslog bind address")
    ap.add_argument("--port", default="514",
                    help="syslog port(s), comma-separated (default 514; e.g. 514,10514)")
    ap.add_argument("--protocol", choices=["udp", "tcp", "both"], default="both")
    ap.add_argument("--db", default="siem.db", help="SQLite path (fallback if no db-config.json / --db-config)")
    ap.add_argument("--db-config", default=None, help="path to db-config.json (sqlite/postgres selector)")
    ap.add_argument("--auth-config", default=None, help="path to auth-config.json (login/OAuth/SAML)")
    ap.add_argument("--dashboard-host", default="127.0.0.1")
    ap.add_argument("--dashboard-port", type=int, default=8080)
    ap.add_argument("--no-dashboard", action="store_true", help="run the listener only")
    args = ap.parse_args()

    db_cfg = dbmod.load_config(args.db_config, sqlite_fallback=args.db)
    print(f"[db] backend: {dbmod.describe(db_cfg)}")

    # Resolve syslog listen ports. Precedence:
    #   1. --port on the command line (explicit override), else
    #   2. "listen_ports" saved in the config file by configure-db.py, else
    #   3. default 514.
    port_arg_given = any(a == "--port" or a.startswith("--port=") for a in sys.argv[1:])
    if port_arg_given:
        try:
            ports = [int(p.strip()) for p in str(args.port).split(",") if p.strip()]
        except ValueError:
            print(f"[error] invalid --port value: {args.port!r}", file=sys.stderr)
            sys.exit(1)
    else:
        ports = db_cfg.get("listen_ports") or [int(p.strip()) for p in str(args.port).split(",") if p.strip()]
    if not ports:
        ports = [514]
    print(f"[listen] syslog ports: {', '.join(map(str, ports))}")
    storage = Storage(db_config=db_cfg)
    engine = RuleEngine(storage)
    forwarders = ForwarderManager(storage, listen_port=ports[0])
    ioc = IOCMatcher(storage)
    fields = FieldIndexer(storage)

    def on_message(raw: str, source_ip: str):
        event = parse_syslog(raw, source_ip)
        log_id = storage.insert_log(event)
        engine.process(log_id, event)
        ioc.process(log_id, event)
        fields.process(log_id, event)
        forwarders.forward(event)
        sev = event["severity"] or "-"
        print(f"[{event['received_at']}] {source_ip} [{sev}] {event['message'][:120]}")

    threads = []
    for p in ports:
        if args.protocol in ("udp", "both"):
            threads.append(threading.Thread(
                target=udp_listener, args=(args.host, p, on_message), daemon=True))
        if args.protocol in ("tcp", "both"):
            threads.append(threading.Thread(
                target=tcp_listener, args=(args.host, p, on_message), daemon=True))

    if not args.no_dashboard:
        dashboard.DB_CONFIG = db_cfg
        dashboard.init_auth(args.auth_config)
        # Let the dashboard's HTTP API receiver push logs through the SAME
        # pipeline the syslog listener uses (parse->store->rules->ioc->fields->
        # forward), so API-ingested logs are processed identically.
        dashboard.set_ingest_hook(on_message, storage)
        dashboard.start_triage_worker()
        dashboard.start_automation_workers()
        threads.append(threading.Thread(
            target=lambda: dashboard.app.run(
                host=args.dashboard_host, port=args.dashboard_port,
                debug=False, use_reloader=False),
            daemon=True))

    for t in threads:
        t.start()

    dash = ("disabled" if args.no_dashboard
            else f"http://{args.dashboard_host}:{args.dashboard_port}")
    print(f"mini-SIEM running — syslog {args.protocol} on {args.host}:{','.join(map(str, ports))}, "
          f"dashboard: {dash}, db: {dbmod.describe(db_cfg)}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
