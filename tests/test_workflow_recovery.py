"""Recovered workflow contracts, with synthetic data and no real providers."""
from types import SimpleNamespace
import pytest
import db
from session_helpers import sign_in,set_role

H={'X-CSRF-Token':'t'}


@pytest.fixture
def workspace(tmp_path,monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard,'DB_CONFIG',db.config_from_path(str(tmp_path/'workflow.db')))
    dashboard.init_auth(None);c=dashboard.app.test_client();sign_in(dashboard,c,'workflow-admin')
    return dashboard,c


def seed(dashboard,n):
    conn=dashboard.get_conn()
    for i in range(n):
        conn.execute('INSERT INTO logs(received_at,hostname,message,severity) VALUES(?,?,?,?)',('2026-10-27T00:00:00+00:00','same-host',f'event {i}','notice'))
        conn.execute('INSERT INTO alerts(created_at,rule_name,severity,description,log_ids) VALUES(?,?,?,?,?)',('2026-10-27T00:00:00+00:00','workflow-rule','warning',f'alert {i}',''))
    conn.commit();conn.close()


def test_ai_off_draft_test_does_not_save_or_enable(workspace,monkeypatch):
    dashboard,c=workspace;from web_blueprints import ai
    before=dashboard.get_ai_config();seen=[]
    def llm(cfg):seen.append(cfg);return SimpleNamespace(test=lambda:(True,'synthetic connection succeeded'))
    monkeypatch.setattr(ai._svc,'llm_from_config',llm)
    r=c.post('/api/ai/test',headers=H,json={'ai_model':'unsaved-model','ai_base_url':'http://127.0.0.1:1234/v1','ai_enabled':True})
    assert r.status_code==200 and r.json['ok']
    assert seen[0]['ai_model']=='unsaved-model' and seen[0]['ai_enabled']=='false'
    assert dashboard.get_ai_config()==before


def test_saved_key_cannot_be_sent_to_changed_draft_address(workspace,monkeypatch):
    dashboard,c=workspace;from web_blueprints import ai
    cfg={**dashboard.get_ai_config(),'ai_api_key':'synthetic-saved-key'}
    monkeypatch.setattr(ai._svc,'get_ai_config',lambda:cfg)
    monkeypatch.setattr(ai._svc,'llm_from_config',lambda *a:pytest.fail('must not connect'))
    r=c.post('/api/ai/test',headers=H,json={'ai_base_url':'https://changed.example/v1'})
    assert r.status_code==400 and 'saved key is not sent' in r.json['error']
    assert 'synthetic-saved-key' not in r.text


@pytest.mark.parametrize('body',[[],{'ai_mode':'bad'},{'ai_api_style':'bad'},{'ai_mode':'external','ai_base_url':'http://untrusted.example/v1'}])
def test_invalid_ai_draft_rejected_without_network(workspace,monkeypatch,body):
    _,c=workspace;from web_blueprints import ai
    monkeypatch.setattr(ai._svc,'llm_from_config',lambda *a:pytest.fail('must not connect'))
    assert c.post('/api/ai/test',headers=H,json=body).status_code==400


def test_log_history_snapshot_sort_and_legacy_contract(workspace):
    dashboard,c=workspace;seed(dashboard,7)
    assert isinstance(c.get('/api/logs?limit=2').json,list)
    first=c.get('/api/logs?page=1&limit=2&sort=received_at&dir=asc&hostname=same-host').json
    assert first['has_more'] and first['next_offset']==2
    seed(dashboard,2)
    second=c.get(f"/api/logs?page=1&limit=2&sort=received_at&dir=asc&hostname=same-host&offset=2&snapshot={first['snapshot']}").json
    assert len(second['items'])==2
    ids=[r['id'] for r in first['items']+second['items']]
    assert len(set(ids))==4 and all(i<=first['snapshot'] for i in ids)
    assert c.get('/api/logs?page=1&limit=2').json['snapshot']>first['snapshot']


@pytest.mark.parametrize('query',['offset=-1','offset=100001','snapshot=-1','snapshot=abc','limit=abc'])
def test_bad_log_history_positions_are_400(workspace,query):
    _,c=workspace;assert c.get('/api/logs?page=1&'+query).status_code==400


def test_extracted_sort_pages_are_stable_and_cap_disclosed(workspace):
    dashboard,c=workspace;seed(dashboard,7);conn=dashboard.get_conn()
    for row in conn.execute('SELECT id FROM logs').fetchall():
        conn.execute('INSERT INTO log_fields(log_id,field,value) VALUES(?,?,?)',(row['id'],'rank',str(row['id'])))
    conn.commit();conn.close()
    first=c.get('/api/logs?page=1&sort=x_rank&dir=asc&fields=rank&limit=3').json
    second=c.get(f"/api/logs?page=1&sort=x_rank&dir=asc&fields=rank&limit=3&offset=3&snapshot={first['snapshot']}").json
    assert first['sort_limit']==100000
    assert [r['id'] for r in first['items']+second['items']]==[1,2,3,4,5,6]


def test_alert_history_is_keyset_and_bulk_triage_still_available(workspace):
    dashboard,c=workspace;seed(dashboard,7)
    first=c.get('/api/alerts?limit=3').json
    seed(dashboard,1)
    second=c.get('/api/alerts?limit=3&before_id='+str(first[-1]['id'])).json
    assert len(second)==3 and not set(r['id'] for r in first)&set(r['id'] for r in second)
    assert c.get('/api/alerts?before_id=bad').status_code==400
    set_role(dashboard,c,'analyst')
    r=c.post('/api/alerts/workflow/bulk',headers=H,json={'ids':[first[0]['id']],'status':'acknowledged'})
    assert r.status_code==200


def test_draft_poller_test_keeps_secrets_events_and_cursor_unwritten(workspace,monkeypatch):
    dashboard,c=workspace;import api_poller
    calls=[]
    def http(self,req,phase,timeout=20):
        calls.append((phase,req))
        if phase=='token':return {'access_token':'synthetic-jwt'}
        if phase=='whoami':return {'id':'tenant','idType':'tenant','apiHosts':{'dataRegion':'https://api-us02.central.sophos.com'}}
        return {'items':[{'id':'synthetic-event'}],'next_cursor':'uncommitted-cursor'}
    monkeypatch.setattr(api_poller._PollerThread,'_http_json',http)
    body={'name':'draft','auth_scheme':'oauth2_sophos','token_url':'https://id.sophos.com/api/v2/oauth2/token',
          'whoami_url':'https://api.central.sophos.com/whoami/v1','events_url':'/siem/v1/events',
          'client_id':'synthetic-client','client_secret':'synthetic-secret','secret_mode':'encrypted','scope':'token','enabled':True}
    r=c.post('/api/pollers/test',headers=H,json=body)
    assert r.status_code==200 and r.json['ok'] and len(calls)==3
    assert calls[1][1].headers.get('Authorization')=='Bearer synthetic-jwt'
    assert calls[2][1].headers.get('X-tenant-id')=='tenant'
    conn=dashboard.get_conn()
    for table in ('api_pollers','logs'):
        assert conn.execute('SELECT COUNT(*) AS n FROM '+table).fetchone()['n']==0
    conn.close()
    assert 'synthetic-secret' not in r.text


@pytest.mark.parametrize('url',['/api/ai/test','/api/pollers/test'])
def test_draft_tests_require_csrf_and_admin(workspace,url):
    dashboard,c=workspace
    assert c.post(url,json={}).status_code==403
    for role in ('viewer','analyst'):
        set_role(dashboard,c,role);assert c.post(url,json={},headers=H).status_code==403
