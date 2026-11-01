"""Compatibility of the recovered machine reader with hardened browser auth."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import jsonschema
import auth
import db
import dashboard
import dashboard_connector as connector
from session_helpers import sign_in

ROOT = Path(__file__).resolve().parents[1]
TABLES = {
    'dashboard_reader_tokens', 'dashboard_export_counters',
    'dashboard_export_records', 'dashboard_export_snapshots',
    'dashboard_export_snapshot_records',
}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, 'DB_CONFIG', db.config_from_path(str(tmp_path/'reader.db')))
    monkeypatch.setattr(auth, 'load_auth_config', lambda *_: json.loads(json.dumps(auth.DEFAULT_AUTH_CONFIG)))
    dashboard.init_auth(None)
    monkeypatch.setattr(connector, '_requests', connector.defaultdict(connector.deque))
    monkeypatch.setattr(connector, '_active', connector.defaultdict(int))
    monkeypatch.setattr(connector, '_global_active', 0)
    conn = dashboard.get_conn()
    try:
        token, _ = connector.create_reader_token(conn, 'recovery-reader', 'recovery-tenant')
    finally:
        conn.close()
    return dashboard.app.test_client(), {'Authorization': 'Bearer '+token}


@pytest.mark.parametrize('role', ['viewer', 'analyst', 'admin'])
def test_browser_identity_does_not_authorize_reader(workspace, role):
    client, _ = workspace
    sign_in(dashboard, client, 'browser-'+role, role)
    response = client.get(connector.PREFIX+'/health')
    assert response.status_code == 401
    assert response.json['error']['code'] == 'AUTH_REQUIRED'


def test_reader_and_browser_have_independent_boundaries(workspace):
    client, headers = workspace
    with client.session_transaction() as s:
        s.update(user='deleted-browser-user', role='admin', auth_stamp='stale')
    assert client.get(connector.PREFIX+'/health', headers=headers).status_code == 200
    # A reader token grants neither browser identity nor administrator mutation.
    assert client.post('/api/pollers/test', json={}, headers=headers).status_code in (401, 403)
    assert client.get('/api/users', headers=headers).status_code == 401
    assert client.get(connector.PREFIX+'-extra/health', headers=headers).status_code == 401


@pytest.mark.parametrize('method', ['post', 'put', 'patch', 'delete'])
def test_machine_mutation_is_rejected_without_csrf_bypass_of_browser_routes(workspace, method):
    client, headers = workspace
    response = getattr(client, method)(connector.PREFIX+'/alerts', json={}, headers=headers)
    assert response.status_code == 403
    assert response.json['error']['code'] == 'FORBIDDEN'
    assert response.headers['Cache-Control'] == 'no-store'
    assert client.get(connector.PREFIX+'/health').status_code == 401


def test_authentication_database_failure_is_structured_503(workspace, monkeypatch):
    client, headers = workspace
    def unavailable(): raise RuntimeError('synthetic database detail must not leak')
    monkeypatch.setattr(connector, '_services', SimpleNamespace(get_conn=unavailable))
    response = client.get(connector.PREFIX+'/health', headers=headers)
    assert response.status_code == 503
    assert response.json['error']['code'] == 'TEMPORARY_UNAVAILABLE'
    assert response.headers['Retry-After'] == '5'
    assert 'synthetic database detail' not in response.text


def test_owner_schema_idempotency_and_runtime_required_tables(workspace):
    config = dashboard.DB_CONFIG
    db.initialize(config)
    conn = db.connect(config)
    try:
        present = {r['name'] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert TABLES <= present
        assert conn.execute('SELECT COUNT(*) AS n FROM dashboard_reader_tokens').fetchone()['n'] == 1
    finally:
        conn.close()
    assert TABLES <= set(db.RUNTIME_REQUIRED_TABLES)
    for backend in ('sqlite', 'postgres'):
        statements = '\n'.join(db._schema_statements(backend))
        assert all('CREATE TABLE IF NOT EXISTS '+name in statements for name in TABLES)


def test_all_live_reader_documents_validate_against_recovered_schemas(workspace):
    client, headers = workspace
    schemas = ROOT/'schemas/operator_workspace'
    control = jsonschema.Draft202012Validator(json.loads((schemas/'control.schema.json').read_text()))
    page = jsonschema.Draft202012Validator(json.loads((schemas/'page.schema.json').read_text()))
    for lane in ('health', 'capabilities', 'alerts', 'incidents', 'assets', 'health-observations'):
        response = client.get(connector.PREFIX+'/'+lane, headers=headers)
        assert response.status_code == 200
        (control if lane in ('health', 'capabilities') else page).validate(response.json)


def test_unknown_machine_path_has_no_redirect_and_returns_json(workspace):
    client, headers = workspace
    response = client.get(connector.PREFIX+'/unknown/path', headers=headers)
    assert response.status_code == 404 and 'Location' not in response.headers
    assert response.content_type == 'application/json; charset=utf-8'
    assert response.json['error']['code'] == 'NOT_FOUND'


def test_snapshot_capacity_returns_retryable_503(workspace, monkeypatch):
    client, headers = workspace
    monkeypatch.setenv('MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS', '1')
    assert client.get(connector.PREFIX+'/alerts', headers=headers).status_code == 200
    response = client.get(connector.PREFIX+'/alerts', headers=headers)
    assert response.status_code == 503
    assert response.json['error']['code'] == 'TEMPORARY_UNAVAILABLE'
    assert response.headers['Retry-After'] == '60'


def test_unexportable_native_identity_returns_structured_422(workspace):
    client, headers = workspace
    conn = dashboard.get_conn()
    try:
        conn.execute('INSERT INTO logs(received_at,hostname,message) VALUES(?,?,?)',
                     ('2026-10-28T00:00:00+00:00', 'x'*513, 'synthetic oversized identity'))
        conn.commit()
    finally:
        conn.close()
    response = client.get(connector.PREFIX+'/assets', headers=headers)
    assert response.status_code == 422
    assert response.json['error']['code'] == 'RECORD_UNEXPORTABLE'


@pytest.mark.parametrize('table', sorted(TABLES))
def test_owner_setup_rejects_runtime_owned_connector_tables(table):
    from tools import postgres_privilege_boundary as boundary
    class Cursor:
        def execute(self, sql, *args): self.sql = sql
        def fetchall(self): return [(table, 'minisiem_dashboard')]
    cursor = Cursor()
    with pytest.raises(RuntimeError, match='runtime identities own protected tables'):
        boundary._assert_roles_do_not_own_protected_tables(cursor, ('minisiem_dashboard',))
    assert all(name in cursor.sql for name in TABLES)


def test_truth_gate_still_checks_delivered_source_mirror(tmp_path, monkeypatch):
    from tools import check_placeholder_truth as gate
    monkeypatch.setattr(gate, 'ROOT', tmp_path)
    inventory = tmp_path/'PLACEHOLDER_TRUTH_INVENTORY.json'
    inventory.write_text(json.dumps({'runtime_placeholders_reclassified': [],
                                    'trivial_tests_reclassified': [], 'tool_scaffolds_reclassified': []}))
    monkeypatch.setattr(gate, 'INVENTORY', inventory)
    mirror = tmp_path/'return/mini-siem/source'
    example = mirror/'integrations/sophos_poller_bundle/integration_example.py'
    example.parent.mkdir(parents=True)
    example.write_text('"""Adapter skeleton."""\nEXAMPLE_ONLY=True\n')
    assert gate.main() == 0
    example.write_text('"""Adapter skeleton."""\n')
    assert gate.main() == 1
    example.write_text('"""Adapter skeleton."""\nEXAMPLE_ONLY=True\n')
    (mirror/'unfinished.py').write_text('"""Scaffold only."""\n')
    assert gate.main() == 1
