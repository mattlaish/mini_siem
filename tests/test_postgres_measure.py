"""Read-only production measurement tool and the CIDR host-bits fix."""
import os
import sys
from pathlib import Path

import dashboard

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import postgres_search_measure as measure  # noqa: E402


def test_page_urls_become_api_filters():
    api = measure.page_url_to_api(
        "https://siem.example/?q=denied&src=10.1.2.3%2F24&host=web&dest=8.8.8.8&sev=warning"
        "&f=act%3Ddeny&f=DPT%3D53&op=or&from=2026-11-07T10:00&dst_port=53&page=1&limit=500")
    assert api == {"q": "denied", "source_ip": "10.1.2.3/24", "hostname": "web", "destination": "8.8.8.8",
                   "severity": "warning", "f_act": "deny", "f_dpt": "53", "fc_op": "or",
                   "from": "2026-11-07T10:00:00+00:00", "dst_port": "53"}
    assert measure.page_url_to_api("f_user=alice*&scope=all") == {"f_user": "alice*", "scope": "all"}


def test_every_connection_is_read_only(monkeypatch):
    monkeypatch.delenv("PGOPTIONS", raising=False)
    measure._read_only_env(30000)
    opts = os.environ["PGOPTIONS"]
    assert "default_transaction_read_only=on" in opts and "statement_timeout=30000" in opts
    assert "lock_timeout=2000" in opts


def test_cidr_with_host_bits_searches_the_network():
    sql, params = dashboard._base_match_clause("l.source_ip", "source", "cidr", "10.1.2.3/24", backend="postgres_v2")
    assert sql == "l.src_ip <<= ?::cidr" and params == ["10.1.2.0/24"]   # PostgreSQL cidr rejects host bits
    sql, params = dashboard._base_match_clause("l.destination", "destination", "cidr", "2001:db8::1/64",
                                               backend="postgres_v2")
    assert params == ["2001:db8::/64"]
