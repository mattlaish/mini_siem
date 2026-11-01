from pathlib import Path


INDEX = Path(__file__).resolve().parents[1] / "templates" / "index.html"


def _html():
    return INDEX.read_text(encoding="utf-8")


def test_timeline_uses_native_dialog_not_custom_overlay():
    html = _html()
    assert '<dialog id="timelineDialog"' in html
    assert 'timeline-overlay' not in html
    assert '.showModal()' in html
    assert "timelineDialogEl.addEventListener('close'" in html
    assert "timelineDialogEl.addEventListener('cancel'" in html


def test_timeline_desktop_and_mobile_sizing_and_horizontal_scrolling():
    html = _html()
    assert 'width:min(1600px,90vw)' in html
    assert 'height:85vh' in html
    assert 'width:100vw' in html
    assert 'height:100dvh' in html
    assert 'overflow-x:auto' in html


def test_timeline_event_can_locate_log_outside_current_page():
    html = _html()
    assert 'async function focusTimelineLog(logId)' in html
    assert 'await loadLogs({focusId:id})' in html
    assert "focusedParams.set('ids', String(focusId))" in html
    assert "row.classList.add('timeline-focus-row')" in html
