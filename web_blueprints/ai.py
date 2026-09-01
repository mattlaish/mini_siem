from flask import Blueprint, jsonify, request
import ai_soc

bp = Blueprint("ai_api", __name__)
_svc = None


def configure(services):
    global _svc
    _svc = services


def _ai_enabled():
    return _svc.get_ai_config()["ai_enabled"] == "true"


@bp.get("/api/ai/config")
def api_ai_config_get():
    cfg = _svc.get_ai_config()
    return jsonify({
        "ai_enabled": cfg["ai_enabled"] == "true",
        "ai_mode": cfg.get("ai_mode", "local"), "ai_base_url": cfg["ai_base_url"],
        "ai_model": cfg["ai_model"], "ai_api_key_set": bool(cfg["ai_api_key"]),
        "ai_auto_triage": cfg.get("ai_auto_triage", "true") == "true",
        "ai_auto_triage_min_severity": cfg.get("ai_auto_triage_min_severity", ""),
        "ai_auto_triage_max_age_hours": int(cfg.get("ai_auto_triage_max_age_hours", "0") or 0),
        "ai_system_prompt": cfg.get("ai_system_prompt", ""),
        "ai_user_template": cfg.get("ai_user_template", ""),
        "ai_max_tokens": int(cfg.get("ai_max_tokens", "900") or 900),
        "ai_default_system_prompt": ai_soc.TRIAGE_SYSTEM,
    })


@bp.post("/api/ai/config")
def api_ai_config_set():
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    updates = {}
    if "ai_enabled" in body: updates["ai_enabled"] = "true" if body["ai_enabled"] else "false"
    if "ai_mode" in body: updates["ai_mode"] = "external" if body["ai_mode"] == "external" else "local"
    if "ai_base_url" in body: updates["ai_base_url"] = str(body["ai_base_url"]).strip()
    if "ai_model" in body: updates["ai_model"] = str(body["ai_model"]).strip()
    if "ai_auto_triage" in body: updates["ai_auto_triage"] = "true" if body["ai_auto_triage"] else "false"
    if "ai_auto_triage_min_severity" in body: updates["ai_auto_triage_min_severity"] = str(body["ai_auto_triage_min_severity"]).strip()
    if "ai_auto_triage_max_age_hours" in body:
        try: updates["ai_auto_triage_max_age_hours"] = str(max(0, min(int(body["ai_auto_triage_max_age_hours"] or 0), 8760)))
        except (TypeError, ValueError): pass
    if "ai_system_prompt" in body: updates["ai_system_prompt"] = str(body["ai_system_prompt"])[:8000]
    if "ai_user_template" in body: updates["ai_user_template"] = str(body["ai_user_template"])[:8000]
    if "ai_max_tokens" in body:
        try: updates["ai_max_tokens"] = str(max(64, min(int(body["ai_max_tokens"] or 900), 8192)))
        except (TypeError, ValueError): pass
    if body.get("ai_api_key"): updates["ai_api_key"] = str(body["ai_api_key"]).strip()
    _svc.save_ai_config(updates)
    sensitive, summarize = {"ai_api_key"}, {"ai_system_prompt", "ai_user_template"}
    parts = []
    for k, v in updates.items():
        if k in sensitive: parts.append(f"{k} (updated)")
        elif k in summarize: parts.append(f"{k} ({'set' if str(v).strip() else 'cleared'})")
        else: parts.append(f"{k}={v}")
    _svc.audit("ai_config_changed", detail=", ".join(parts) or "no changes")
    return jsonify({"ok": True})


@bp.post("/api/ai/test")
def api_ai_test():
    if not _ai_enabled(): return jsonify({"ok": False, "error": "AI Analyst is turned off. Enable it first."}), 400
    cfg = _svc.get_ai_config()
    if cfg.get("ai_mode") == "external" and not cfg.get("ai_api_key"):
        return jsonify({"ok": False, "error": "External mode needs an API token — none is set."}), 400
    ok, detail = _svc.llm_from_config().test()
    return jsonify({"ok": True, "detail": detail}) if ok else (jsonify({"ok": False, "error": detail}), 502)


@bp.get("/api/ai/queue/stats")
def api_ai_queue_stats():
    conn = _svc.get_conn()
    def cnt(clause):
        r = conn.execute("SELECT COUNT(*) AS c FROM alerts WHERE " + clause).fetchone()
        return r["c"] if hasattr(r, "keys") else r[0]
    return jsonify({"queued": cnt("ai_status IS NULL OR ai_status = 'pending'"), "failed": cnt("ai_status = 'error'"), "done": cnt("ai_status = 'done'"), "skipped": cnt("ai_status = 'skipped'")})


@bp.post("/api/ai/queue/retry")
def api_ai_queue_retry():
    conn = _svc.get_conn(); cur = conn.execute("UPDATE alerts SET ai_status='pending', ai_attempts=0 WHERE ai_status IS NULL OR ai_status IN ('error','pending','skipped')"); conn.commit()
    n = cur.rowcount if hasattr(cur, "rowcount") else -1; _svc.audit("ai_queue_retry", detail=f"{n} alerts reset for re-triage")
    return jsonify({"ok": True, "reset": n})


@bp.post("/api/ai/queue/clear")
def api_ai_queue_clear():
    conn = _svc.get_conn(); cur = conn.execute("UPDATE alerts SET ai_status='skipped' WHERE ai_status IS NULL OR ai_status IN ('pending','error')"); conn.commit()
    n = cur.rowcount if hasattr(cur, "rowcount") else -1; _svc.audit("ai_queue_cleared", detail=f"{n} alerts marked skipped")
    return jsonify({"ok": True, "cleared": n})


@bp.post("/api/ai/triage")
def api_ai_triage():
    if not _ai_enabled(): return jsonify({"error": "AI Analyst is turned off. Enable it on the AI page."}), 400
    body = request.get_json(force=True, silent=True) or {}; alert_id = body.get("alert_id")
    if not alert_id: return jsonify({"error": "alert_id is required"}), 400
    conn = _svc.get_conn()
    alert = conn.execute("SELECT id, source_ip FROM alerts WHERE id=?", (int(alert_id),)).fetchone()
    if not alert: return jsonify({"error": "alert not found"}), 404
    cfg = _svc.get_ai_config()
    try:
        result = ai_soc.run_progressive_triage(
            conn,
            int(alert_id),
            _svc.llm_from_config(),
            max_tokens=int(cfg.get("ai_max_tokens", "900") or 900),
            system_prompt=cfg.get("ai_system_prompt"),
            user_template=cfg.get("ai_user_template"),
        )
    except Exception as exc: return jsonify({"error": f"LLM call failed: {type(exc).__name__}: {exc}"}), 502
    stages = result["stages"]
    final_ctx = result.get("final_context") or {}
    return jsonify({
        "answer": result["analysis"],
        "context_summary": {
            "source": alert["source_ip"],
            "profile": stages[-1].get("profile") if stages else "",
            "final_stage": stages[-1].get("stage") if stages else "",
            "stages_run": [s.get("stage") for s in stages],
            "candidate_events": stages[-1].get("candidate_count", 0) if stages else 0,
            "evidence_events": stages[-1].get("evidence_count", 0) if stages else 0,
            # Backward-compatible keys consumed by the existing AI page.
            "related_events": len(final_ctx.get("related") or []),
            "source_history_events": len(final_ctx.get("src_history") or []),
            "entity_ip": final_ctx.get("entity_ip", ""),
        },
    })


@bp.post("/api/ai/chat")
def api_ai_chat():
    if not _ai_enabled(): return jsonify({"error": "AI Analyst is turned off. Enable it on the AI page."}), 400
    body = request.get_json(force=True, silent=True) or {}; question = (body.get("question") or "").strip(); history = body.get("history") or []
    if not question: return jsonify({"error": "question is required"}), 400
    conn = _svc.get_conn(); ctx = ai_soc.gather_chat_context(conn, question); cfg = _svc.get_ai_config(); messages = ai_soc.build_chat_messages(ctx, question, history, system_prompt=cfg.get("ai_system_prompt"))
    try: answer = _svc.llm_from_config().chat(messages, max_tokens=int(cfg.get("ai_max_tokens", "900") or 900))
    except Exception as exc: return jsonify({"error": f"LLM call failed: {type(exc).__name__}: {exc}"}), 502
    return jsonify({"answer": answer, "context_summary": {"matched_events": len(ctx["matches"]), "keywords": ctx["keywords"]}})
