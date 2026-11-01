"""Persistence helpers for AI provider configuration and usage accounting.

Kept independent of Flask so encryption/migration/audit behavior can be tested
without the web runtime. Prompts, model output, and API keys are never written
to ``ai_usage_audit``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import ai_secret


def load_config(conn, defaults: dict) -> dict:
    rows = {r["key"]: r["value"] for r in
            conn.execute("SELECT key, value FROM app_config").fetchall()}
    cfg = dict(defaults)
    for key in defaults:
        if key == "ai_api_key":
            continue
        if key in rows and rows[key] is not None:
            cfg[key] = rows[key]

    encrypted = rows.get("ai_api_key_encrypted") or ""
    legacy_plain = rows.get("ai_api_key") or ""
    if encrypted:
        cfg["ai_api_key"] = ai_secret.decrypt_api_key(encrypted)
    elif legacy_plain:
        # Backward-compatible one-time migration. The plaintext row is removed
        # only after a replacement ciphertext has been written successfully.
        token = ai_secret.encrypt_api_key(legacy_plain)
        conn.execute(
            "INSERT INTO app_config(key,value) VALUES('ai_api_key_encrypted',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (token,))
        conn.execute("DELETE FROM app_config WHERE key='ai_api_key'")
        conn.commit()
        cfg["ai_api_key"] = legacy_plain
    return cfg


def save_config(conn, defaults: dict, updates: dict) -> None:
    for key, value in updates.items():
        if key == "ai_api_key":
            token = ai_secret.encrypt_api_key(str(value or ""))
            conn.execute(
                "INSERT INTO app_config(key,value) VALUES('ai_api_key_encrypted',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (token,))
            conn.execute("DELETE FROM app_config WHERE key='ai_api_key'")
        elif key in defaults:
            conn.execute(
                "INSERT INTO app_config(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    conn.commit()


def record_usage(conn, event: dict, *, at: str | None = None) -> None:
    at = at or datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO ai_usage_audit "
        "(at,provider,api_style,model,endpoint_host,request_id,client_request_id,status,http_status,"
        "input_tokens,output_tokens,total_tokens,cached_tokens,reasoning_tokens,"
        "retry_count,latency_ms,error_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            at,
            str(event.get("provider") or "compatible")[:64],
            str(event.get("api_style") or "")[:64],
            str(event.get("model") or "")[:200],
            str(event.get("endpoint_host") or "")[:255],
            str(event.get("request_id") or "")[:255],
            str(event.get("client_request_id") or "")[:512],
            str(event.get("status") or "unknown")[:32],
            int(event.get("http_status") or 0),
            int(event.get("input_tokens") or 0),
            int(event.get("output_tokens") or 0),
            int(event.get("total_tokens") or 0),
            int(event.get("cached_tokens") or 0),
            int(event.get("reasoning_tokens") or 0),
            int(event.get("retry_count") or 0),
            int(event.get("latency_ms") or 0),
            str(event.get("error_code") or "")[:120],
        ),
    )
    conn.commit()
