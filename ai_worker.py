"""
mini-SIEM automatic triage worker
==================================
Proactively sends potential threats (alerts) to the local LLM for
analysis as they occur, instead of waiting for an analyst to request it.

Why a background worker (and not inline):
  Alerts are raised synchronously by the listener the instant a rule
  fires — that path must stay fast, because anything slow there stalls
  ingest and drops packets. An LLM call takes seconds. So triage is
  decoupled: the listener just writes the alert (ai_status='pending'),
  and THIS worker — running in the dashboard process, off the hot path —
  drains pending alerts to the LLM one at a time and stores the result.

  The alerts table is effectively a durable queue: if the LLM is down or
  disabled, alerts simply stay 'pending' and are picked up later. Failed
  calls are retried up to max_attempts, then marked 'error' so one bad
  alert can't wedge the queue.

get_settings() is supplied by the dashboard and returns:
    {"enabled": bool, "auto_triage": bool, "min_severity": str, "llm": LLMClient}
get_conn() returns a fresh db.Connection.
"""

import threading
import time
from datetime import datetime, timezone, timedelta

import ai_soc
import severity as severity_mod


class TriageWorker:
    def __init__(self, get_conn, get_settings, poll_interval=5,
                 batch=5, max_attempts=3):
        self.get_conn = get_conn
        self.get_settings = get_settings
        self.poll_interval = poll_interval
        self.batch = batch
        self.max_attempts = max_attempts
        self._thread = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("[triage] auto-triage worker started")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval)
            if self._stop.is_set():
                break
            try:
                self.run_once()
            except Exception as exc:
                print(f"[triage] cycle error: {type(exc).__name__}: {exc}")

    # -- one drain cycle (also directly callable in tests) ------------------

    def run_once(self) -> int:
        settings = self.get_settings()
        if not settings.get("enabled") or not settings.get("auto_triage"):
            return 0

        conn = self.get_conn()
        processed = 0
        try:
            pending = conn.execute(
                """SELECT id, created_at, rule_name, severity, source_ip,
                          description, log_ids, ai_attempts
                   FROM alerts
                   WHERE (ai_status IS NULL OR ai_status = 'pending')
                     AND (ai_attempts IS NULL OR ai_attempts < ?)
                   ORDER BY id ASC LIMIT ?""",
                (self.max_attempts, self.batch)).fetchall()

            min_sev = settings.get("min_severity") or ""
            min_idx = severity_mod.index_of(min_sev) if min_sev else None
            llm = settings.get("llm")

            max_age_h = int(settings.get("max_age_hours") or 0)
            for alert in pending:
                if self._stop.is_set():
                    break
                alert_id = alert["id"]

                # skip alerts older than the configured backlog window
                if max_age_h > 0:
                    try:
                        created = datetime.fromisoformat(alert["created_at"])
                        age_h = (datetime.now(timezone.utc) - created).total_seconds() / 3600
                        if age_h > max_age_h:
                            conn.execute(
                                "UPDATE alerts SET ai_status='skipped' WHERE id=?", (alert_id,))
                            conn.commit()
                            continue
                    except (TypeError, ValueError):
                        pass

                # skip below-threshold alerts permanently
                if min_idx is not None:
                    a_idx = severity_mod.index_of(alert["severity"])
                    if a_idx > min_idx:
                        conn.execute(
                            "UPDATE alerts SET ai_status='skipped' WHERE id=?", (alert_id,))
                        conn.commit()
                        continue

                # De-duplicate triage work: if an identical alert (same rule +
                # source) was already analyzed recently, copy that result
                # instead of paying for another LLM call. This is what stops a
                # 49-deep burst of the same firewall_deny_burst from costing 49
                # analyses. Only reuse when auto-grouping would consider them
                # the same (rule_name + source_ip) and the prior analysis is
                # from the last 6 hours.
                if settings.get("dedup_groups", True):
                    try:
                        twin = conn.execute(
                            """SELECT ai_analysis FROM alerts
                               WHERE rule_name = ? AND (source_ip IS ? OR source_ip = ?)
                                 AND ai_status = 'done' AND ai_analysis IS NOT NULL
                                 AND created_at >= ?
                               ORDER BY id DESC LIMIT 1""",
                            (alert["rule_name"], alert["source_ip"], alert["source_ip"],
                             (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat())
                        ).fetchone()
                    except Exception:
                        twin = None
                    if twin and twin["ai_analysis"]:
                        note = ("[grouped: identical to a recently analyzed alert "
                                "from the same rule and source]\n\n") + twin["ai_analysis"]
                        conn.execute(
                            """UPDATE alerts SET ai_status='done', ai_analysis=?,
                                   ai_triaged_at=? WHERE id=?""",
                            (note, datetime.now(timezone.utc).isoformat(), alert_id))
                        conn.commit()
                        processed += 1
                        continue

                ctx = ai_soc.gather_alert_context(conn, alert_id)
                if not ctx:
                    conn.execute(
                        "UPDATE alerts SET ai_status='error', ai_analysis=? WHERE id=?",
                        ("context could not be gathered", alert_id))
                    conn.commit()
                    continue

                messages = ai_soc.build_triage_messages(
                    ctx, system_prompt=settings.get("system_prompt"),
                    user_template=settings.get("user_template"))
                try:
                    answer = llm.chat(messages, max_tokens=int(settings.get("max_tokens") or 900))
                    conn.execute(
                        """UPDATE alerts
                           SET ai_status='done', ai_analysis=?, ai_triaged_at=?
                           WHERE id=?""",
                        (answer, datetime.now(timezone.utc).isoformat(), alert_id))
                    conn.commit()
                    processed += 1
                    print(f"[triage] analyzed alert #{alert_id} ({alert['rule_name']})")
                except Exception as exc:
                    attempts = (alert["ai_attempts"] or 0) + 1
                    status = "error" if attempts >= self.max_attempts else "pending"
                    conn.execute(
                        "UPDATE alerts SET ai_attempts=?, ai_status=?, ai_analysis=? WHERE id=?",
                        (attempts, status,
                         f"LLM call failed ({type(exc).__name__}): {exc}", alert_id))
                    conn.commit()
                    print(f"[triage] alert #{alert_id} attempt {attempts} failed: {exc}")
                    # LLM likely unreachable — stop this cycle, retry next tick
                    break
        finally:
            conn.close()
        return processed
