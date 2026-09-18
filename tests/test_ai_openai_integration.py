import json
import sqlite3
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ai_config_store
import ai_secret
import ai_soc


class _Handler(BaseHTTPRequestHandler):
    responses = []
    requests = []

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "payload": payload,
        })
        status, headers, body = type(self).responses.pop(0)
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _server(responses):
    _Handler.responses = list(responses)
    _Handler.requests = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv


def _config_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE app_config (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE ai_usage_audit (
            at TEXT NOT NULL,
            provider TEXT NOT NULL,
            api_style TEXT NOT NULL,
            model TEXT NOT NULL,
            endpoint_host TEXT,
            request_id TEXT,
            client_request_id TEXT,
            status TEXT NOT NULL,
            http_status INTEGER DEFAULT 0,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            cached_tokens INTEGER DEFAULT 0,
            reasoning_tokens INTEGER DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            latency_ms INTEGER DEFAULT 0,
            error_code TEXT
        );
    """)
    return conn


def test_openai_auto_selects_responses_api():
    client = ai_soc.LLMClient("https://api.openai.com/v1", "gpt-test", "secret")
    assert client.api_style == "responses"
    assert client.endpoint == "https://api.openai.com/v1/responses"


def test_responses_api_payload_output_usage_and_no_store():
    body = {
        "id": "resp_test",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "ready"}],
        }],
        "usage": {
            "input_tokens": 12,
            "input_tokens_details": {"cached_tokens": 3},
            "output_tokens": 5,
            "output_tokens_details": {"reasoning_tokens": 2},
            "total_tokens": 17,
        },
    }
    srv = _server([(200, {"x-request-id": "req_test"}, body)])
    usage = []
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "gpt-test",
            "sk-test",
            api_style="responses",
            usage_callback=usage.append,
        )
        text = client.chat([
            {"role": "system", "content": "You are a SOC analyst."},
            {"role": "user", "content": "triage this"},
        ], temperature=0.1, max_tokens=321)
    finally:
        srv.shutdown()
        srv.server_close()

    assert text == "ready"
    req = _Handler.requests[0]
    assert req["path"] == "/v1/responses"
    assert req["headers"]["Authorization"] == "Bearer sk-test"
    assert req["headers"].get("X-Client-Request-Id")
    assert req["payload"]["store"] is False
    assert req["payload"]["max_output_tokens"] == 321
    assert req["payload"]["instructions"] == "You are a SOC analyst."
    assert req["payload"]["input"] == [{"role": "user", "content": "triage this"}]
    assert "temperature" not in req["payload"]

    assert len(usage) == 1
    event = usage[0]
    assert event["status"] == "success"
    assert event["request_id"] == "req_test"
    assert event["client_request_id"]
    assert event["input_tokens"] == 12
    assert event["output_tokens"] == 5
    assert event["cached_tokens"] == 3
    assert event["reasoning_tokens"] == 2
    assert event["total_tokens"] == 17


def test_429_retry_after_then_success_records_retry_count():
    success = {
        "output_text": "ok",
        "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
    }
    srv = _server([
        (429, {"Retry-After": "0", "x-request-id": "req_rate"}, {"error": {"type": "rate_limit_error"}}),
        (200, {"x-request-id": "req_ok"}, success),
    ])
    sleeps = []
    usage = []
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "gpt-test",
            api_style="responses",
            max_retries=2,
            sleep_fn=sleeps.append,
            random_fn=lambda: 0.0,
            usage_callback=usage.append,
        )
        assert client.chat([{"role": "user", "content": "hello"}]) == "ok"
    finally:
        srv.shutdown()
        srv.server_close()

    assert len(_Handler.requests) == 2
    assert sleeps == [0.0]
    assert usage[-1]["status"] == "success"
    assert usage[-1]["retry_count"] == 1
    assert usage[-1]["request_id"] == "req_ok"


def test_terminal_429_is_audited_as_error():
    srv = _server([
        (429, {"x-request-id": "req_rate_final"}, {"error": {"type": "rate_limit_error"}}),
    ])
    usage = []
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "gpt-test",
            api_style="responses",
            max_retries=0,
            usage_callback=usage.append,
        )
        try:
            client.chat([{"role": "user", "content": "hello"}])
            assert False, "expected HTTPError"
        except Exception as exc:
            assert getattr(exc, "code", None) == 429
    finally:
        srv.shutdown()
        srv.server_close()

    assert usage[-1]["status"] == "error"
    assert usage[-1]["http_status"] == 429
    assert usage[-1]["error_code"] == "http_429"
    assert usage[-1]["request_id"] == "req_rate_final"


def test_chat_completions_compatibility_is_preserved():
    body = {
        "choices": [{"message": {"content": "compat-ready"}}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9},
    }
    srv = _server([(200, {}, body)])
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "local-model",
            api_style="auto",
        )
        assert client.api_style == "chat_completions"
        assert client.chat([{"role": "user", "content": "hello"}], max_tokens=99) == "compat-ready"
    finally:
        srv.shutdown()
        srv.server_close()
    req = _Handler.requests[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["payload"]["max_tokens"] == 99
    assert req["payload"]["stream"] is False


def test_ai_secret_master_is_outside_db_and_owner_only(tmp_path, monkeypatch):
    master = tmp_path / "ai-master.key"
    monkeypatch.setenv("MINISIEM_AI_SECRET_MASTER_FILE", str(master))
    token = ai_secret.encrypt_api_key("sk-sensitive-value")
    assert master.exists()
    assert stat.S_IMODE(master.stat().st_mode) == 0o600
    assert "sk-sensitive-value" not in token
    assert ai_secret.decrypt_api_key(token) == "sk-sensitive-value"


def test_decrypt_missing_master_fails_without_creating_replacement(tmp_path, monkeypatch):
    master = tmp_path / "missing-master.key"
    monkeypatch.setenv("MINISIEM_AI_SECRET_MASTER_FILE", str(master))
    original_master = ai_secret.load_or_create_master(master)
    token = ai_secret.encrypt_api_key("sk-restore-sensitive")
    master.unlink()
    assert not master.exists()
    try:
        ai_secret.decrypt_api_key(token)
        assert False, "expected missing-master failure"
    except RuntimeError as exc:
        assert "restore the original master" in str(exc)
    assert not master.exists()
    # prove the ciphertext still decrypts after the original external master
    # is restored rather than a replacement being generated.
    master.write_text(original_master + "\n", encoding="ascii")
    master.chmod(0o600)
    assert ai_secret.decrypt_api_key(token) == "sk-restore-sensitive"


def test_config_store_migrates_plaintext_key_and_audits_metadata_only(tmp_path, monkeypatch):
    master = tmp_path / "ai-master.key"
    monkeypatch.setenv("MINISIEM_AI_SECRET_MASTER_FILE", str(master))
    conn = _config_db()
    conn.execute("INSERT INTO app_config(key,value) VALUES('ai_api_key',?)", ("sk-legacy-plaintext",))
    conn.commit()

    defaults = {"ai_api_key": "", "ai_model": "gpt-test", "ai_api_style": "auto"}
    cfg = ai_config_store.load_config(conn, defaults)
    assert cfg["ai_api_key"] == "sk-legacy-plaintext"

    rows = {r["key"]: r["value"] for r in conn.execute(
        "SELECT key,value FROM app_config WHERE key IN ('ai_api_key','ai_api_key_encrypted')"
    ).fetchall()}
    assert "ai_api_key" not in rows
    assert "ai_api_key_encrypted" in rows
    assert "sk-legacy-plaintext" not in rows["ai_api_key_encrypted"]
    assert ai_secret.decrypt_api_key(rows["ai_api_key_encrypted"]) == "sk-legacy-plaintext"

    event = {
        "provider": "openai", "api_style": "responses", "model": "gpt-test",
        "endpoint_host": "api.openai.com", "request_id": "req_audit",
        "client_request_id": "client_audit", "status": "success", "http_status": 200,
        "input_tokens": 10, "output_tokens": 4, "total_tokens": 14,
        "cached_tokens": 2, "reasoning_tokens": 1, "retry_count": 1,
        "latency_ms": 250, "error_code": "",
        # These must be ignored by persistence even if a caller accidentally
        # puts them in an event dictionary.
        "api_key": "sk-never-store", "prompt": "sensitive log context",
    }
    ai_config_store.record_usage(conn, event, at="2026-09-18T00:00:00+00:00")
    row = conn.execute("SELECT * FROM ai_usage_audit WHERE request_id='req_audit'").fetchone()
    assert row["provider"] == "openai"
    assert row["api_style"] == "responses"
    assert row["total_tokens"] == 14
    assert row["retry_count"] == 1
    columns = {r[1] for r in conn.execute("PRAGMA table_info(ai_usage_audit)").fetchall()}
    assert "api_key" not in columns
    assert "prompt" not in columns


def test_config_store_new_key_never_writes_plaintext(tmp_path, monkeypatch):
    master = tmp_path / "ai-master.key"
    monkeypatch.setenv("MINISIEM_AI_SECRET_MASTER_FILE", str(master))
    conn = _config_db()
    defaults = {"ai_api_key": "", "ai_model": "gpt-test", "ai_api_style": "auto"}
    ai_config_store.save_config(conn, defaults, {"ai_api_key": "sk-new-secret"})
    rows = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM app_config").fetchall()}
    assert "ai_api_key" not in rows
    assert ai_secret.decrypt_api_key(rows["ai_api_key_encrypted"]) == "sk-new-secret"


def test_external_mode_requires_https_but_explicit_loopback_dev_exception_exists():
    try:
        ai_soc.LLMClient("http://example.com/v1", "gpt-test", external_mode=True)
        assert False, "expected insecure external endpoint rejection"
    except ValueError as exc:
        assert "must use HTTPS" in str(exc)

    client = ai_soc.LLMClient(
        "http://127.0.0.1:9999/v1",
        "local-dev",
        external_mode=True,
        allow_insecure_loopback_external=True,
    )
    assert client.endpoint.endswith("/chat/completions")


def test_external_strict_redaction_masks_identifiers_and_raw_evidence():
    text = (
        "Description: user alice@example.com from 10.10.20.30\n"
        "#7 now src=10.10.20.30 host=workstation01 app=sshd sev=warning | user=alice login failed\n"
        "IPv6 2001:db8::10 username: bob"
    )
    redacted = ai_soc.redact_outbound_text(text, "strict")
    assert "10.10.20.30" not in redacted
    assert "2001:db8::10" not in redacted
    assert "alice@example.com" not in redacted
    assert "workstation01" not in redacted
    assert "username: bob" not in redacted
    assert "Description: <message-redacted>" in redacted
    assert "| <message-redacted>" in redacted


def test_external_identifier_redaction_keeps_event_semantics():
    text = "#7 now src=10.0.0.8 host=host01 sev=warning | user=alice failed SSH password"
    redacted = ai_soc.redact_outbound_text(text, "identifiers")
    assert "10.0.0.8" not in redacted
    assert "host01" not in redacted
    assert "user=alice" not in redacted
    assert "failed SSH password" in redacted


def test_openai_chat_completions_uses_max_completion_tokens():
    client = ai_soc.LLMClient(
        "https://api.openai.com/v1",
        "gpt-test",
        "secret",
        api_style="chat_completions",
        external_mode=True,
        redaction_policy="none",
    )
    payload = client._payload([{"role": "user", "content": "hello"}], 0.2, 77)
    assert payload["max_completion_tokens"] == 77
    assert "max_tokens" not in payload


def test_responses_incomplete_is_not_accepted_as_success():
    body = {
        "id": "resp_incomplete",
        "status": "incomplete",
        "incomplete_details": {"reason": "max_output_tokens"},
        "output": [],
        "usage": {"input_tokens": 4, "output_tokens": 2, "total_tokens": 6},
    }
    srv = _server([(200, {"x-request-id": "req_incomplete"}, body)])
    usage = []
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "gpt-test",
            api_style="responses",
            usage_callback=usage.append,
        )
        try:
            client.chat([{"role": "user", "content": "hello"}])
            assert False, "expected incomplete Responses API error"
        except ai_soc.LLMResponseError as exc:
            assert exc.status == "incomplete"
            assert "max_output_tokens" in str(exc)
    finally:
        srv.shutdown()
        srv.server_close()
    assert usage[-1]["status"] == "error"
    assert usage[-1]["error_code"] == "response_incomplete"
    assert usage[-1]["request_id"] == "req_incomplete"


def test_responses_failed_is_not_accepted_as_success():
    body = {
        "id": "resp_failed",
        "status": "failed",
        "error": {"code": "server_error", "message": "provider failed"},
        "output": [],
    }
    srv = _server([(200, {}, body)])
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "gpt-test",
            api_style="responses",
        )
        try:
            client.chat([{"role": "user", "content": "hello"}])
            assert False, "expected failed Responses API error"
        except ai_soc.LLMResponseError as exc:
            assert exc.status == "failed"
            assert "provider failed" in str(exc)
    finally:
        srv.shutdown()
        srv.server_close()


def test_transient_url_error_is_retried_then_succeeds(monkeypatch):
    success = {"status": "completed", "output_text": "ready"}
    srv = _server([(200, {}, success)])
    original = ai_soc.urllib.request.urlopen
    calls = {"n": 0}
    sleeps = []

    def flaky(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ai_soc.urllib.error.URLError("temporary network failure")
        return original(req, timeout=timeout)

    monkeypatch.setattr(ai_soc.urllib.request, "urlopen", flaky)
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "gpt-test",
            api_style="responses",
            max_retries=1,
            backoff_base=0,
            sleep_fn=sleeps.append,
        )
        assert client.chat([{"role": "user", "content": "hello"}]) == "ready"
    finally:
        srv.shutdown()
        srv.server_close()
    assert calls["n"] == 2
    assert sleeps == [0.0]


def test_connection_probe_uses_reasoning_safe_output_budget(monkeypatch):
    client = ai_soc.LLMClient("http://127.0.0.1:9999/v1", "local-test")
    seen = {}

    def fake_chat(messages, temperature=0.2, max_tokens=900):
        seen["max_tokens"] = max_tokens
        return "ready"

    monkeypatch.setattr(client, "chat", fake_chat)
    ok, detail = client.test()
    assert ok is True
    assert "ready" in detail
    assert seen["max_tokens"] == ai_soc.DEFAULT_TEST_MAX_TOKENS == 128


def test_external_mode_redacts_the_actual_wire_payload():
    body = {"status": "completed", "output_text": "ready"}
    srv = _server([(200, {}, body)])
    try:
        client = ai_soc.LLMClient(
            f"http://127.0.0.1:{srv.server_port}/v1",
            "dev-external",
            api_style="responses",
            external_mode=True,
            redaction_policy="strict",
            allow_insecure_loopback_external=True,
        )
        assert client.chat([{
            "role": "user",
            "content": "Description: secret detail\n#1 now src=10.1.2.3 host=corp01 | user=alice failed login",
        }]) == "ready"
    finally:
        srv.shutdown()
        srv.server_close()
    wire = json.dumps(_Handler.requests[0]["payload"], sort_keys=True)
    for secret in ("10.1.2.3", "corp01", "user=alice", "secret detail", "failed login"):
        assert secret not in wire
    assert "<message-redacted>" in wire


def test_external_redaction_and_https_controls_are_wired_to_config_and_ui():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    dashboard = (root / "dashboard.py").read_text(encoding="utf-8")
    blueprint = (root / "web_blueprints" / "ai.py").read_text(encoding="utf-8")
    page = (root / "templates" / "ai.html").read_text(encoding="utf-8")
    assert '"ai_external_redaction": "strict"' in dashboard
    assert 'external_mode=cfg.get("ai_mode", "local") == "external"' in dashboard
    assert "validate_external_endpoint" in blueprint
    assert "MINISIEM_AI_ALLOW_INSECURE_LOOPBACK_EXTERNAL" in blueprint
    assert 'id="externalRedaction"' in page
    assert "ai_external_redaction" in page
    assert "HTTPS-only" in page
