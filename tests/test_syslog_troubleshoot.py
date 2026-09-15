import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "syslog_capture_helper.py"


def _load_helper():
    spec = importlib.util.spec_from_file_location("syslog_capture_helper", HELPER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_capture_filter_is_constrained_to_source_and_configured_ports():
    mod = _load_helper()
    tokens = mod._filter_tokens("192.0.2.25", [514, 10514])
    assert tokens[:4] == ["src", "host", "192.0.2.25", "and"]
    assert " ".join(tokens).find("dst port 514") >= 0
    assert "10514" in tokens
    assert "-A" not in tokens
    assert "-X" not in tokens


def test_invalid_ip_is_rejected_before_capture(capsys):
    mod = _load_helper()
    rc = mod.main(["--source-ip", "127.0.0.1;id", "--seconds", "1"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert data["ok"] is False
    assert "valid IPv4 or IPv6" in data["error"]


def test_helper_uses_ports_from_db_config(tmp_path, monkeypatch):
    mod = _load_helper()
    db_cfg = tmp_path / "db-config.json"
    db_cfg.write_text(json.dumps({"listen_ports": [514, 10514, 514]}))
    helper_cfg = tmp_path / "capture.json"
    helper_cfg.write_text(json.dumps({"db_config_path": str(db_cfg)}))
    monkeypatch.setattr(mod, "HELPER_CONFIG", helper_cfg)
    assert mod._load_ports() == [514, 10514]


def test_setup_contains_troubleshoot_tab_and_no_custom_filter_box():
    text = (ROOT / "templates" / "setup.html").read_text()
    assert 'data-target="sec-troubleshoot"' in text
    assert 'id="troubleSourceIp"' in text
    assert 'id="troubleCaptureBtn"' in text
    assert "/api/troubleshoot/syslog-capture" in text
    assert "custom packet filters" in text


def test_dashboard_uses_fixed_helper_and_shell_free_subprocess():
    text = (ROOT / "dashboard.py").read_text()
    assert '_SYSLOG_CAPTURE_HELPER = "/usr/local/libexec/mini-siem-syslog-capture"' in text
    assert '["sudo", "-n", _SYSLOG_CAPTURE_HELPER' in text
    assert "shell=True" not in text
    assert '@admin_required\ndef api_troubleshoot_syslog_capture' in text


def test_helper_capture_reports_header_only_packet_summary(tmp_path, monkeypatch, capsys):
    mod = _load_helper()
    db_cfg = tmp_path / "db-config.json"
    db_cfg.write_text(json.dumps({"listen_ports": [514]}))
    helper_cfg = tmp_path / "capture.json"
    helper_cfg.write_text(json.dumps({"db_config_path": str(db_cfg)}))
    monkeypatch.setattr(mod, "HELPER_CONFIG", helper_cfg)

    fake = tmp_path / "tcpdump"
    fake.write_text("#!/bin/sh\necho 'IP 192.0.2.25.55123 > 10.0.0.5.514: UDP, length 123'\n")
    fake.chmod(0o755)
    monkeypatch.setattr(mod.shutil, "which", lambda name: str(fake) if name == "tcpdump" else None)

    rc = mod.main(["--source-ip", "192.0.2.25", "--seconds", "1"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["ok"] is True
    assert data["seen"] is True
    assert data["packets"] == 1
    assert data["udp_packets"] == 1
    assert data["ports"] == [514]
    assert "UDP, length 123" in data["samples"][0]
