#!/usr/bin/env python3
"""Measure actual Log Search requests on a dedicated, local synthetic cluster.

The server must be started with minisiem.benchmark=on. Each run creates a
new, uniquely named database; it never truncates or drops an existing one.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
from statistics import median
import sys
from time import perf_counter
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ANCHOR = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)


def fixture(start, span, count):
    for i in range(count):
        at = (start + span * (i / count)).isoformat()
        vendor = ('FortiGate', 'Windows', 'Sophos')[i % 3]
        ip = f'192.0.2.{1 + i % 100}'
        fields = dict(act='Deny' if i % 7 == 0 else 'Allow',
                      dpt='53' if i % 3 == 0 else '443', policyid=str(i % 11),
                      srcip=ip, dstip='198.51.100.53', user=f'User{i % 550}',
                      query=f'host-{i % 500}.example.test', vendor=vendor)
        fields.update({f'field{k}': f'value-{i % (k + 2)}' for k in range(28 if i % 3 == 0 else 6)})
        message = f'{vendor} {fields["act"]} {fields["query"]} {"suspicious" if i % 127 == 0 else "normal"}'
        yield ({
            'received_at': at, 'device_timestamp': at, 'source_ip': ip, 'peer_ip': ip,
            'format': 'json', 'priority': 132, 'facility': 'auth', 'severity': 'warning',
            'hostname': f'host-{i % 500}', 'destination': fields['dstip'], 'app_name': vendor,
            'proc_id': '', 'msg_id': '', 'message': message, 'raw': json.dumps(fields),
        }, fields)


def workloads():
    return {
        'recent': {}, 'cidr': {'source_ip': '192.0.2.0/26'},
        'host_prefix': {'hostname': 'host-12'}, 'word': {'q': 'suspicious'},
        'port_range': {'dst_port': '50-55'},
        'exact_one': {'f_act': 'deny'},
        'exact_three': {'f_act': 'deny', 'f_dpt': '53', 'f_policyid': '2'},
        'prefix': {'f_user': 'user12*'}, 'contains': {'f_query': '*example.test*'},
        'or_exclusion': {'f_act': 'deny', 'f_dpt': '53', 'f_user': '!user12*', 'fc_op': 'or'},
        'field_sort': {'fields': 'user', 'sort': 'x_user'},
    }


def _plan_summary(plan):
    root = plan['Plan']
    relations = set()
    def visit(node):
        if node.get('Actual Loops', 0) and node.get('Relation Name'):
            relations.add(node['Relation Name'])
        for child in node.get('Plans', []):
            visit(child)
    visit(root)
    return {'planning_ms': plan['Planning Time'], 'execution_ms': plan['Execution Time'],
            'shared_hit_blocks': root.get('Shared Hit Blocks', 0),
            'shared_read_blocks': root.get('Shared Read Blocks', 0),
            'relations_executed': sorted(relations)}


def measure(client, conn, repeats):
    from db import Connection
    original = Connection.execute
    output = {}
    for name, filters in workloads().items():
        calls, timings = [], []
        def track(self, sql, params=()):
            if sql.lstrip().upper().startswith('SELECT'):
                calls.append((sql, list(params)))
            return original(self, sql, params)
        query = dict(filters, page='1', limit='100', **{
            'from': (ANCHOR - timedelta(days=1)).isoformat(), 'to': ANCHOR.isoformat()})
        with patch.object(Connection, 'execute', track):
            for _ in range(repeats + 1):
                calls.clear()
                start = perf_counter()
                response = client.get('/api/logs', query_string=query)
                timings.append(1000 * (perf_counter() - start))
                if response.status_code != 200:
                    raise RuntimeError(f'{name}: HTTP {response.status_code}')
        timings = sorted(timings[1:])
        plans = []
        for sql, params in calls:
            row = conn.execute('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + sql, params).fetchone()
            plan = next(iter(row.values()))[0]
            plans.append({'sql': sql, **_plan_summary(plan), 'plan': plan})
        output[name] = {'p50_ms': median(timings), 'p95_ms': timings[math.ceil(.95 * repeats)-1],
                        'ids': [r['id'] for r in response.json['items']], 'statements': plans}
    return output


def run(args):
    import psycopg2
    from psycopg2 import sql
    import dashboard
    import db
    from listener import Storage
    kwargs = dict(host='127.0.0.1', port=args.port, user=args.user, connect_timeout=4,
                  password=os.environ.get('PGPASSWORD', ''))
    name = 'minisiem_bench_' + uuid.uuid4().hex[:12]
    admin = psycopg2.connect(dbname='postgres', **kwargs)
    try:
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute("SELECT current_setting('minisiem.benchmark', true)")
            if cur.fetchone()[0] != 'on':
                raise RuntimeError('Refusing to write: dedicated benchmark cluster marker is absent')
            cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    finally:
        admin.close()
    cfg = {'backend': 'postgres', 'postgres': {**kwargs, 'dbname': name,
           'connect_retries': 1}}
    # Leaving --layout unset also lets the same harness run on pre-change code.
    if args.layout is not None:
        cfg['postgres']['partition_granularity'] = args.layout
    db.initialize(cfg)
    dashboard.DB_CONFIG = cfg
    client = dashboard.app.test_client()
    conn = db.connect(cfg)
    storage = Storage(db_config=cfg)
    old_start = ANCHOR - timedelta(days=args.history_days + 1)
    months = (ANCHOR.year - old_start.year) * 12 + ANCHOR.month - old_start.month + 1
    result = {'database': name, 'version': conn.execute('SELECT version() AS v').fetchone()['v'],
              'hot_rows': args.hot, 'history_rows': args.history, 'history_days': args.history_days,
              'repeats': args.repeats, 'requested_layout': args.layout, 'phases': {}}
    try:
        conn.execute("SET TIME ZONE 'UTC'")
        conn.execute('SELECT public.minisiem_ensure_security_event_partitions(?::timestamptz, ?)',
                     (old_start.isoformat(), months))
        conn.commit()
        for label, start, span, n in (
                ('hot_only', ANCHOR-timedelta(days=1), timedelta(days=1), args.hot),
                ('with_history', old_start, timedelta(days=args.history_days), args.history)):
            iterator = iter(fixture(start, span, n))
            import itertools
            begin = perf_counter()
            batch_ms = []
            while batch := list(itertools.islice(iterator, 250)):
                _, elapsed = storage.insert_log_batch(batch)
                batch_ms.append(elapsed)
            ingest_s = perf_counter()-begin
            for relation in ('logs', 'log_fields', 'security_events'):
                conn.execute('ANALYZE '+relation)
            conn.commit()
            result['phases'][label] = {
                'ingest_rows_per_second': n / max(ingest_s, .001),
                'batch_commit_p50_ms': median(batch_ms) if batch_ms else None,
                'sizes': [dict(r) for r in conn.execute(
                    """SELECT relname, pg_table_size(oid) AS table_bytes,
                              pg_indexes_size(oid) AS index_bytes
                         FROM pg_class WHERE relname IN ('logs','log_fields')
                            OR oid IN (SELECT relid FROM pg_partition_tree('security_events') WHERE isleaf)
                         ORDER BY relname""").fetchall()],
                'search': measure(client, conn, args.repeats),
            }
    finally:
        storage.close()
        conn.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--user', default='bench')
    parser.add_argument('--hot', type=int, default=2000)
    parser.add_argument('--history', type=int, default=10000)
    parser.add_argument('--history-days', type=int, default=120)
    parser.add_argument('--repeats', type=int, default=12)
    parser.add_argument('--layout', choices=('month', 'week', 'day'))
    parser.add_argument('--json-out', type=Path, required=True)
    args = parser.parse_args()
    if not (1 <= args.port <= 65535 and 1 <= args.hot <= 100000
            and 1 <= args.history <= 1000000 and 1 <= args.history_days <= 365
            and 3 <= args.repeats <= 100):
        parser.error('benchmark settings out of bounds')
    with args.json_out.open('x', encoding='utf-8') as out:
        json.dump(run(args), out, indent=2, default=str)
    print(args.json_out)


if __name__ == '__main__':
    main()
