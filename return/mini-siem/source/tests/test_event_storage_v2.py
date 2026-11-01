import ast
import ipaddress
from pathlib import Path

import db
import event_storage_v2 as es

ROOT = Path(__file__).resolve().parents[1]


class _Severity:
    @staticmethod
    def synonyms_of(value):
        return [str(value).lower()]


class Args(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def _dashboard_query_helpers():
    path = ROOT / "dashboard.py"
    wanted = {
        "_fts_token", "_fts_build_match", "_postgres_tsquery_token", "_like_escape",
        "_parse_field_filter", "_field_value_predicate", "_concept_match_mode",
        "_base_match_clause", "_alias_match_clause", "_concept_clause",
        "_concept_filter_terms", "_build_log_query",
    }
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = {
        "re": __import__("re"),
        "ipaddress": ipaddress,
        "severity_mod": _Severity,
        "get_search_aliases": lambda: {"source": [], "host": [], "destination": []},
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), ns)
    return ns


def test_postgres_event_storage_v2_schema_contract():
    ddl = "\n".join(es.postgres_schema_statements())
    assert "PARTITION BY RANGE (event_time)" in ddl
    assert "event_time TIMESTAMPTZ" in ddl
    assert "ingested_at TIMESTAMPTZ" in ddl
    assert "src_ip INET" in ddl and "dst_ip INET" in ddl
    assert "fields JSONB" in ddl
    for idx in (
        "idx_se_src_ip_time", "idx_se_dst_ip_time", "idx_se_asset_time",
        "idx_se_identity_time", "idx_se_type_time",
    ):
        assert idx in ddl
    # Retired as unused/redundant: no query filters `fields` with GIN operators,
    # and BRIN(event_time) duplicates the (event_time, id) primary key.
    assert "idx_se_fields_gin" not in ddl
    assert "idx_se_event_time_brin" not in ddl
    assert "security_events_default" in ddl
    assert "minisiem_ensure_security_event_partitions" in ddl
    assert "p_months < 1 OR p_months > 24" in ddl
    assert "CREATE OR REPLACE VIEW security_event_context" in ddl
    assert "LEFT JOIN assets" in ddl and "LEFT JOIN identities" in ddl


def test_postgres_runtime_requires_v2_tables_and_migration_ledger_advances():
    assert {"security_events", "assets", "identities"}.issubset(set(db.RUNTIME_REQUIRED_TABLES))
    assert len(db._migrations()) == 41


def test_projection_normalization_uses_native_values_and_preserves_raw():
    event = {
        "received_at": "2026-09-19T00:00:01+00:00",
        "device_timestamp": "2026-09-19T00:00:00+00:00",
        "source_ip": "10.1.2.3",
        "peer_ip": "192.0.2.10",
        "destination_ip": "10.9.8.7",
        "destination_port": "443",
        "hostname": "sensor01",
        "severity": "warning",
        "format": "cef",
        "priority": 132,
        "facility": "auth",
        "app_name": "edge",
        "proc_id": "",
        "msg_id": "",
        "message": "user=Alice act=blocked",
        "raw": "CEF:0|Vendor|Product|1|100|Blocked|4|src=10.1.2.3",
        "device_vendor": "Vendor",
        "device_product": "Product",
        "event_name": "Blocked",
        "signature_id": "100",
    }
    p = es.normalized_projection(event, {"user": "Alice", "spt": "51514"})
    assert p["src_ip"] == "10.1.2.3"
    assert p["dst_ip"] == "10.9.8.7"
    assert p["peer_ip"] == "192.0.2.10"
    assert p["src_port"] == 51514 and p["dst_port"] == 443
    assert p["user_name"] == "Alice"
    assert p["vendor"] == "Vendor" and p["product"] == "Product"
    assert p["event_code"] == "100"
    assert p["raw_event"].startswith("CEF:0")
    assert p["event_time"] == "2026-09-19T00:00:00+00:00"


def test_postgres_query_semantics_use_native_ip_time_and_prefix_indexes():
    build = _dashboard_query_helpers()["_build_log_query"]
    sql, params = build(
        Args({
            "source_ip": "10.1.2.3",
            "hostname": "dc01",
            "destination": "*database*",
            "from": "2026-09-18T00:00:00+00:00",
        }),
        "l.id,l.received_at,l.source_ip,l.hostname,l.destination",
        search_backend="postgres_v2",
    )
    assert "FROM security_event_logs l" in sql
    assert "l.src_ip = ?::inet" in sql
    assert "lower(l.hostname) LIKE ?" in sql
    assert "lower(l.destination) LIKE ?" in sql
    assert "l.event_time >= ?::timestamptz" in sql
    assert "ORDER BY l.event_time DESC" in sql
    assert "10.1.2.3" in params
    assert "dc01%" in params
    assert "%database%" in params

    sql2, params2 = build(
        Args({"source_ip": "10.1.2.0/24"}),
        "l.id,l.source_ip",
        search_backend="postgres_v2",
    )
    assert "l.src_ip <<= ?::cidr" in sql2
    assert "10.1.2.0/24" in params2


def test_archive_privilege_and_phase4_paths_are_v2_aware():
    archive_src = (ROOT / "archive.py").read_text(encoding="utf-8")
    privilege_src = (ROOT / "tools" / "postgres_privilege_boundary.py").read_text(encoding="utf-8")
    phase4_src = (ROOT / "tools" / "postgres_phase4_validation.py").read_text(encoding="utf-8")
    assert 'delete_in("security_events", "legacy_log_id", chunk)' in archive_src
    assert "GRANT DELETE ON TABLE public.security_events" in privilege_src
    assert "minisiem_ensure_security_event_partitions" in privilege_src
    assert "Storage.insert_log_batch" in phase4_src
    assert "INSERT INTO logs" not in phase4_src


def test_partition_lifecycle_is_bounded_and_installed_for_split_postgres():
    installer = (ROOT / "install-services.sh").read_text(encoding="utf-8")
    maintenance = (ROOT / "tools" / "postgres_event_partition_maintenance.py").read_text(encoding="utf-8")
    privilege = (ROOT / "tools" / "postgres_privilege_boundary.py").read_text(encoding="utf-8")
    assert "mini-siem-event-partitions.timer" in installer
    assert "postgres_event_partition_maintenance.py" in installer
    assert "--months 3" in installer
    assert "OnCalendar=" in installer and "Persistent=true" in installer
    assert "db-maintenance-credentials.json" in installer
    assert "minisiem_ensure_security_event_partitions" in maintenance
    assert "months < 1 or months > 24" in maintenance
    assert "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES FROM" in privilege
    assert "GRANT SELECT ON TABLES TO" in privilege


def test_privilege_check_covers_v2_projection_entities_and_partition_function():
    checker = (ROOT / "tools" / "postgres_privilege_check.py").read_text(encoding="utf-8")
    assert "can_insert_security_events" in checker
    assert "can_delete_security_events" in checker
    assert "can_insert_assets" in checker
    assert "can_manage_event_partitions" in checker
