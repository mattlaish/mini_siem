"""Operator wording must not alter data values, privileges or UI contracts."""
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest
import db

ROOT = Path(__file__).resolve().parents[1]


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


@pytest.fixture
def language_client(tmp_path, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard, 'DB_CONFIG', db.config_from_path(str(tmp_path / 'copy.db')))
    dashboard.init_auth(None)
    with dashboard.app.test_client() as client:
        with client.session_transaction() as session:
            session.update(user='copy-test', role='admin', must_change=False, csrf_token='copy-token')
        yield client


@pytest.mark.parametrize('route,title', [
    ('/setup', 'Settings'), ('/correlate', 'Investigations'),
    ('/health', 'System Health'), ('/audit', 'Activity History'),
    ('/detection-rules', 'Detection Rules'), ('/execution-windows', 'Approved Hours'),
    ('/help', 'Help'), ('/ai', 'AI Analyst'), ('/security-alerts', 'Alerts'),
])
def test_operator_pages_render_with_product_navigation(language_client, route, title):
    response = language_client.get(route)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert title in html
    assert 'Cloud log connections' in html if route == '/setup' else True
    assert 'static/app.js' in html
    assert 'Checking ingestion' not in html


def test_primary_copy_does_not_explain_internal_implementation(language_client):
    for route in ['/setup', '/health', '/help', '/detection-rules', '/execution-windows']:
        parser = VisibleText()
        parser.feed(language_client.get(route).get_data(as_text=True))
        visible = ' '.join(parser.parts).lower()
        for phrase in ['code-owned', 'data plane', 'iana timezone', 'runtime ddl',
                       'materialized at ingest', 'pipeline correlation', 'monday=0',
                       'schema readiness', 'bookmarks a cursor']:
            assert phrase not in visible, (route, phrase)


def test_provider_protocol_names_and_saved_option_values_are_preserved(language_client):
    html = language_client.get('/setup').get_data(as_text=True)
    for original in ['oauth2_sophos', 'oauth2_client_credentials', 'api_key', 'encrypted',
                     'vaultgate', 'tcp', 'udp', 'octet', 'newline', 'admin', 'analyst', 'viewer']:
        assert f'value="{original}"' in html
    for reference in ['X-Tenant-ID', '/api/ingest', '/siem/v1/events']:
        assert reference in html
    assert 'nothing is missed or duplicated' not in html


def test_sample_preview_has_summary_and_optional_original_details(language_client):
    html = language_client.get('/detection-rules').get_data(as_text=True)
    assert 'id="simulationSummary"' in html
    assert 'View test details (JSON)' in html
    assert 'id="simulationResult"' in html
    assert 'id="simulationEvent"' in html
    assert 'id="simulateRule"' in html


def test_display_labels_keep_unknown_custom_names_and_do_not_modify_api_values():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the shared display-label test')
    code = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const root={setAttribute(){},removeAttribute(){},getAttribute(){return null;}};
const sandbox={window:{},document:{documentElement:root,addEventListener(){}},localStorage:{getItem(){return null;}}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),sandbox);
const label=sandbox.window.MS.label;
assert.equal(label('UNKNOWN'),'Not confirmed');
assert.equal(label('STALE'),'Update overdue');
assert.equal(label('web_server_shell'),'Web server launches a program');
assert.equal(label('process.parent.name'),'Started by');
assert.equal(label('customer-rule_ABC'),'customer-rule_ABC');
assert.equal(label('__proto__'),'__proto__');
assert.equal(label(null),'');
assert.equal(sandbox.window.MS.alertSeverity('error'),'High');
assert.equal(label('error'),'Error');
assert.match(sandbox.window.MS.settingError('Configuration changed; reload before saving'),/Someone else/);
'''
    subprocess.run([node, '-e', code, str(ROOT / 'static/app.js')], check=True, capture_output=True, text=True)


def test_calendar_and_exception_editor_uses_choices_but_preserves_request_schema():
    script = (ROOT / 'static/detection.js').read_text(encoding='utf-8')
    assert "const DAYS=['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']" in script
    assert "key==='weekdays'?Number(el.value):el.value" in script
    assert "if(k==='rule_id')options=" in script
    assert "if(k==='schedule_id')options=" in script
    assert "'out_of_hours_shell','nxlog_severity_event','high_severity_event'" in script
    assert "row[k]=objectValue(e.target,k,type)" in script
    assert 'Discard unsaved changes' in script
    assert "fetch(url,options)" in script


def test_original_evidence_is_not_translated():
    script = (ROOT / 'static/alerts.js').read_text(encoding='utf-8')
    assert '${e.raw}' in script
    assert 'MS.label(e.raw)' not in script
    assert 'MS.label(a.description)' not in script


def test_ai_connection_setup_is_available_before_enabling_analysis():
    html = (ROOT / 'templates/ai.html').read_text(encoding='utf-8')
    assert "$('aiBody').style.pointerEvents" not in html
    assert "['triageBtn','alertSelect','chatSend','chatInput']" in html
    assert 'disabled=!aiEnabled' in html
    assert 'id="settingsPanel"' in html


def test_help_covers_current_workflows_without_claiming_guaranteed_delivery(language_client):
    html = language_client.get('/help').get_data(as_text=True)
    for target in ['getting-started', 'alerts', 'detection', 'search', 'aliases', 'normalization', 'selfmon']:
        assert f'id="{target}"' in html
    assert 'not a guarantee of lossless delivery' in html
    assert 'one serious event or from a pattern' in html
