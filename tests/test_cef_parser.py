import os
import tempfile

import db
from correlations import run_correlation
from listener import Storage, parse_syslog
from normalize import extract_fields


def test_standard_bare_cef_normalizes_core_fields_and_preserves_transport_peer():
    raw = "CEF:0|Acme|EdgeFW|1.2|1001|Blocked connection|8|src=10.1.2.3 dst=192.0.2.9 suser=alice act=blocked dpt=443"
    event = parse_syslog(raw, "203.0.113.10")
    assert event["format"] == "cef"
    assert event["peer_ip"] == "203.0.113.10"
    assert event["source_ip"] == "10.1.2.3"
    assert event["destination"] == "192.0.2.9"
    assert event["username"] == "alice"
    assert event["action"] == "blocked"
    assert event["destination_port"] == "443"
    assert event["device_vendor"] == "Acme"
    assert event["device_product"] == "EdgeFW"
    assert event["signature_id"] == "1001"
    assert event["severity"] == "error"
    assert event["priority"] is None
    assert event["raw"] == raw


def test_rfc3164_wrapped_cef_is_detected_before_generic_syslog_path():
    raw = "<134>Sep 23 12:00:00 relay app: CEF:0|Acme|EDR|7|42|Malware detected|10|src=10.0.0.5 dst=10.0.0.8"
    event = parse_syslog(raw, "198.51.100.7")
    assert event["format"] == "cef"
    assert event["priority"] == 134
    assert event["facility"] == "local0"
    assert event["hostname"] == "relay"
    assert event["app_name"] == "app"
    assert event["peer_ip"] == "198.51.100.7"
    assert event["source_ip"] == "10.0.0.5"
    assert event["severity"] == "critical"


def test_cef_must_start_actual_payload_not_merely_appear_as_quoted_text():
    raw = "<134>Sep 23 12:00:00 relay app: parser rejected sample CEF:0|Acme|FW|1|9|Quoted|8|src=10.0.0.9"
    event = parse_syslog(raw, "198.51.100.7")
    assert event["format"] == "rfc3164"
    assert event["source_ip"] == "10.0.0.9"  # generic src/dst enrichment still applies
    assert event["peer_ip"] == "198.51.100.7"
    assert event["message"].startswith("parser rejected sample CEF:0|")

    unknown = parse_syslog("application says CEF:0|Acme|FW|1|9|Quoted|8|src=10.0.0.10", "192.0.2.9")
    assert unknown["format"] == "unknown"


def test_pri_only_cef_payload_is_supported_without_substring_matching():
    raw = "<134>CEF:0|Acme|FW|1|9|Direct PRI CEF|6|src=10.0.0.5 dst=10.0.0.6"
    event = parse_syslog(raw, "198.51.100.9")
    assert event["format"] == "cef"
    assert event["source_ip"] == "10.0.0.5"
    assert event["peer_ip"] == "198.51.100.9"


def test_cef_extension_keeps_vendor_custom_fields_spaces_and_escaped_equals():
    raw = r"CEF:0|Vendor\|Name|Product|1|77|Custom event|5|cs1Label=Rule Name cs1=Allow VPN Users customKey=value\=with\=equals msg=hello world src=192.0.2.1"
    event = parse_syslog(raw, "203.0.113.1")
    assert event["format"] == "cef"
    assert event["device_vendor"] == "Vendor|Name"
    assert event["_cef"]["cs1Label"] == "Rule Name"
    assert event["_cef"]["cs1"] == "Allow VPN Users"
    assert event["_cef"]["customKey"] == "value=with=equals"
    assert event["_cef"]["msg"] == "hello world"
    assert event["_cef"]["vendor"] == "Vendor|Name"
    assert event["_cef"]["event_code"] == "77"


def test_empty_extension_is_valid_and_malformed_cef_falls_back_without_dropping_raw():
    empty = parse_syslog("CEF:0|Acme|FW|1|9|Empty extension|3|", "192.0.2.1")
    assert empty["format"] == "cef"
    assert empty["_cef"]["vendor"] == "Acme"

    malformed_raw = "CEF:0|too|short"
    malformed = parse_syslog(malformed_raw, "192.0.2.2")
    assert malformed["format"] == "unknown"
    assert malformed["raw"] == malformed_raw


def test_cef_listener_db_search_and_correlation_e2e():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "cef-test.db"))
        storage = Storage(db_config=cfg)
        try:
            raw = "CEF:0|Acme|EdgeFW|1|1001|Blocked connection|8|src=10.20.30.40 dst=192.0.2.50 suser=alice act=blocked dpt=443 cs1Label=Policy cs1=Internet Block"
            event = parse_syslog(raw, "203.0.113.5")
            fields = extract_fields(event["message"], [], json_obj=event["_cef"])
            log_id = storage.insert_log(event, fields=fields)
            storage.conn.commit()

            row = storage.conn.execute(
                "SELECT value FROM log_fields WHERE log_id=? AND field='custom_missing'", (log_id,)
            ).fetchone()
            assert row is None
            assert storage.conn.execute(
                "SELECT value FROM log_fields WHERE log_id=? AND field='cs1'", (log_id,)
            ).fetchone()["value"] == "Internet Block"
            assert storage.conn.execute(
                "SELECT value FROM log_fields WHERE log_id=? AND field='vendor'", (log_id,)
            ).fetchone()["value"] == "Acme"

            result = run_correlation(storage.conn, {
                "type": "threshold",
                "pattern": r"Blocked connection",
                "group_by": "source_ip",
                "threshold": 1,
                "window_minutes": 60,
            })
            assert result["group_count"] == 1
            assert result["groups"][0]["key"] == "10.20.30.40"
        finally:
            storage.close()
