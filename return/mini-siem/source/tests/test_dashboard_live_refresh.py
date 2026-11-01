from pathlib import Path


INDEX = Path(__file__).resolve().parents[1] / "templates" / "index.html"


def _html():
    return INDEX.read_text(encoding="utf-8")


def test_auto_refresh_polls_only_logs_and_stats_at_split_intervals():
    html = _html()
    assert "const LOG_REFRESH_MS = 5000;" in html
    assert "const STATS_REFRESH_MS = 15000;" in html
    assert "setInterval(backgroundLogTick, LOG_REFRESH_MS);" in html
    assert "setInterval(backgroundStatsTick, STATS_REFRESH_MS);" in html
    assert "Auto-refresh intentionally never polls Alerts or the AI queue." in html
    # Manual refresh remains the explicit on-demand path for secondary panels.
    assert "loadAlerts(), loadAiQueue()" in html


def test_background_refresh_is_non_overlapping_and_pauses_when_hidden():
    html = _html()
    assert "if (background && current) return null;" in html
    assert "if (current) current.abort();" in html
    assert "const controller = new AbortController();" in html
    assert "if (!autoRefresh || document.hidden) return;" in html
    assert "'X-Background-Poll':'1'" in html


def test_timeline_is_on_demand_not_rebuilt_by_log_poll():
    html = _html()
    assert 'id="timelineRefresh"' in html
    assert "document.getElementById('timelineRefresh').addEventListener('click', () => loadTimeline({incremental:true}));" in html
    assert "Background log refreshes never" in html
    # loadLogs must not contain the old automatic timeline rebuild hook.
    start = html.index("async function loadLogs(options = {})")
    end = html.index("document.getElementById('refreshBtn')", start)
    assert "loadTimeline()" not in html[start:end]
