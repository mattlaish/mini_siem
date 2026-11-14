from datetime import datetime, timedelta, timezone

import ai_soc
import db
import storage_stats


def test_sqlite_total_stays_exact_and_chat_is_bounded(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "chat.db"))
    db.initialize(cfg)
    conn = db.connect(cfg)
    now = datetime.now(timezone.utc)
    try:
        for when, message in (
            (now - timedelta(days=2), "old task_1 only"),
            (now - timedelta(minutes=2), "literal task_1"),
            (now - timedelta(minutes=1), "taskX1 is not literal"),
            (now + timedelta(hours=2), "future task_1"),
        ):
            conn.execute("INSERT INTO logs(received_at,message) VALUES (?,?)", (when.isoformat(), message))
        conn.commit()
        assert storage_stats.log_total(conn) == (4, False, True)
        ctx = ai_soc.gather_chat_context(conn, "task_1")
        assert ctx["window_hours"] == 24
        assert [row["message"] for row in ctx["matches"]] == ["literal task_1"]
        fallback = ai_soc.gather_chat_context(conn, "unmatchedword")
        assert [row["message"] for row in fallback["matches"]] == ["taskX1 is not literal", "literal task_1"]
        assert "LAST 24 HOURS" in ai_soc.build_chat_messages(ctx, "task_1")[-1]["content"]
    finally:
        conn.close()
