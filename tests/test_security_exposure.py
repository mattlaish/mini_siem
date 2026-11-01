"""Recovered security contracts: isolated accounts, mock providers and loopback IO."""
import json
import socket
import ssl
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import auth
import db
import outbound
from session_helpers import sign_in, set_role

H={"X-CSRF-Token":"t"}


@pytest.fixture
def workspace(tmp_path,monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard,"DB_CONFIG",db.config_from_path(str(tmp_path/'security.db')))
    dashboard.init_auth(None)
    c=dashboard.app.test_client();sign_in(dashboard,c,'security-admin')
    return dashboard,c


@pytest.mark.parametrize('url', ['/api/norm-patterns','/api/norm-reindex','/api/norm-columns','/api/iocs',
    '/api/iocs/import','/api/ioc-feeds','/api/ioc-feeds/1/fetch','/api/ai/queue/clear','/api/ai/queue/retry',
    '/api/ai/triage','/api/ai/chat','/api/ai/config','/api/ai/test','/api/tickets/test','/api/reports/run',
    '/api/reports/schedule','/api/forwarders/1/test','/api/pollers/test','/api/pollers/1/test'])
def test_viewer_cannot_mutate_or_make_costly_requests(workspace,url):
    dashboard,c=workspace;set_role(dashboard,c,'viewer')
    assert c.post(url,json={},headers=H).status_code==403


@pytest.mark.parametrize('url',['/api/norm-patterns','/api/norm-reindex','/api/ioc-feeds',
    '/api/ai/queue/clear','/api/ai/test','/api/pollers/test','/api/tickets/test'])
def test_administrative_actions_reject_analyst(workspace,url):
    dashboard,c=workspace;set_role(dashboard,c,'analyst')
    assert c.post(url,json={},headers=H).status_code==403


def test_db_role_wins_and_legacy_cookie_is_rejected(workspace):
    dashboard,c=workspace;set_role(dashboard,c,'viewer')
    with c.session_transaction() as s:s['role']='admin'
    assert c.get('/api/whoami').json['role']=='viewer'
    assert c.get('/api/users').status_code==403
    with c.session_transaction() as s:s.pop('auth_stamp')
    assert c.get('/api/whoami').status_code==401


def test_delete_and_recreation_revoke_cookie(workspace):
    dashboard,c=workspace;other=dashboard.app.test_client();sign_in(dashboard,other,'victim')
    assert c.delete('/api/users/victim',headers=H).status_code==200
    replacement=dashboard.app.test_client();sign_in(dashboard,replacement,'victim')
    assert other.get('/api/whoami').status_code==401
    assert replacement.get('/api/whoami').status_code==200


def test_password_revokes_peers_not_changing_browser(workspace):
    dashboard,_=workspace;conn=dashboard.get_conn();auth.set_password(conn,'security-admin','old-synthetic-password');conn.close()
    a,b=dashboard.app.test_client(),dashboard.app.test_client()
    for c in (a,b):sign_in(dashboard,c,'security-admin')
    assert a.post('/api/users/password',headers=H,json={'current_password':'old-synthetic-password','new_password':'new-synthetic-password'}).status_code==200
    assert a.get('/api/whoami').status_code==200 and b.get('/api/whoami').status_code==401


def test_login_rotation_open_redirect_and_credential_race(workspace,monkeypatch):
    dashboard,c=workspace;conn=dashboard.get_conn();auth.set_password(conn,'security-admin','synthetic-login-password');conn.close()
    with c.session_transaction() as s:s['old_state']='discard'
    r=c.post('/login',data={'username':'security-admin','password':'synthetic-login-password','next':'//evil.invalid/'})
    assert r.status_code==302 and r.headers['Location']=='/'
    with c.session_transaction() as s:assert 'old_state' not in s and s['csrf_token']!='t'
    original=auth.login_user
    def race(username,*args,**kwargs):
        conn=dashboard.get_conn();auth.set_password(conn,username,'different-password');conn.close()
        return original(username,*args,**kwargs)
    monkeypatch.setattr(auth,'login_user',race)
    c=dashboard.app.test_client()
    r=c.post('/login',data={'username':'security-admin','password':'synthetic-login-password'})
    assert 'Account+changed' in r.headers['Location'] and c.get('/api/whoami').status_code==401


def test_session_store_failure_is_closed(workspace,monkeypatch):
    _,c=workspace
    monkeypatch.setattr(auth,'get_user',lambda *a: (_ for _ in ()).throw(RuntimeError('secret-detail')))
    r=c.get('/api/whoami');assert r.status_code==503 and 'secret-detail' not in r.text


@pytest.mark.parametrize('source',['oauth','saml'])
def test_sso_viewer_default_explicit_roles_and_collision(workspace,source):
    dashboard,_=workspace;conn=dashboard.get_conn()
    assert auth.upsert_sso_user(conn,'sso-viewer',source)['role']=='viewer'
    conn.execute("UPDATE users SET role='analyst' WHERE username='sso-viewer'");conn.commit()
    assert auth.upsert_sso_user(conn,'sso-viewer',source)['role']=='analyst'
    with pytest.raises(ValueError):auth.upsert_sso_user(conn,'admin',source)
    with pytest.raises(ValueError):auth.oauth_identity({}, {})
    conn.close()


@pytest.mark.parametrize('source',['oauth','saml'])
def test_sso_callbacks_use_stored_role(workspace,monkeypatch,source):
    dashboard,c=workspace
    if source=='oauth':
        monkeypatch.setattr(dashboard,'_oauth',SimpleNamespace(sso=SimpleNamespace(authorize_access_token=lambda:{'userinfo':{'email':'new-sso'}})))
        r=c.get('/auth/oauth/callback')
    else:
        saml=SimpleNamespace(process_response=lambda:None,get_errors=lambda:[],is_authenticated=lambda:True,get_nameid=lambda:'new-sso')
        monkeypatch.setattr(auth,'build_saml_auth',lambda *a:saml);r=c.post('/auth/saml/acs')
    assert r.status_code==302 and c.get('/api/whoami').json['role']=='viewer'


@pytest.mark.parametrize('url',['https://127.0.0.1/','https://10.0.0.1/','https://[::1]/',
    'https://169.254.169.254/','https://100.100.100.200/','https://168.63.129.16/',
    'https://[::ffff:127.0.0.1]/','https://metadata.google.internal/','file:///tmp/a',
    'https://user:password@example.invalid/','https://example.invalid:0/','http://example.invalid/'])
def test_blocked_destinations_never_connect(monkeypatch,url):
    monkeypatch.delenv('MINISIEM_OUTBOUND_ALLOWLIST',raising=False)
    with pytest.raises(outbound.OutboundPolicyError):outbound.resolve_destination(url)


def test_origin_exceptions_all_dns_answers_and_metadata(monkeypatch):
    monkeypatch.setenv('MINISIEM_OUTBOUND_ALLOWLIST','https://internal.example:8443')
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.1',8443))])
    assert outbound.resolve_destination('https://internal.example:8443/api')[1]==['10.0.0.1']
    with pytest.raises(outbound.OutboundPolicyError):outbound.resolve_destination('https://internal.example/api')
    monkeypatch.setenv('MINISIEM_OUTBOUND_ALLOWLIST','')
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443)) for ip in ['1.1.1.1','127.0.0.1']])
    with pytest.raises(outbound.OutboundPolicyError):outbound.resolve_destination('https://mixed.example/')
    monkeypatch.setenv('MINISIEM_OUTBOUND_ALLOWLIST','http://169.254.169.254')
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('169.254.169.254',80))])
    with pytest.raises(outbound.OutboundPolicyError):outbound.resolve_destination('http://169.254.169.254/')


class Handler(BaseHTTPRequestHandler):
    calls=[]
    def log_message(self,*a):pass
    def do_GET(self):
        self.calls.append((self.path,dict(self.headers)))
        if self.path=='/redirect':
            self.send_response(302);self.send_header('Location','/target');self.end_headers();return
        if self.path=='/error':
            self.send_response(503);self.end_headers();self.wfile.write(b'secret-provider-body');return
        self.send_response(200)
        if self.path!='/stream':self.send_header('Content-Length','100')
        self.end_headers()
        if self.path=='/slow':time.sleep(.5)
        try:self.wfile.write(b'x'*(10 if self.path=='/short' else 100))
        except OSError:pass


@pytest.fixture
def server(monkeypatch):
    Handler.calls=[];srv=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
    base=f'http://127.0.0.1:{srv.server_port}';monkeypatch.setenv('MINISIEM_OUTBOUND_ALLOWLIST',base)
    yield base
    srv.shutdown();srv.server_close();thread.join(timeout=2)


def test_redirect_and_error_do_not_leak_credentials(server):
    req=urllib.request.Request(server+'/redirect',headers={'Authorization':'Bearer synthetic','X-API-Key':'synthetic'})
    with pytest.raises(urllib.error.HTTPError) as e:outbound.open_request(req)
    assert e.value.code==302 and len(Handler.calls)==1
    with pytest.raises(urllib.error.HTTPError) as e:outbound.open_request(urllib.request.Request(server+'/error'))
    assert e.value.code==503 and e.value.read()==b'' and 'secret-provider-body' not in str(e.value)


@pytest.mark.parametrize('path',['/large','/stream','/short'])
def test_response_overflow_and_incomplete_body_fail(server,path):
    with pytest.raises(outbound.OutboundPolicyError):
        outbound.open_request(urllib.request.Request(server+path),max_bytes=16 if path!='/short' else 200)


def test_deadline_and_invalid_header_redaction(server):
    started=time.monotonic()
    with pytest.raises((urllib.error.URLError,TimeoutError)):outbound.open_request(urllib.request.Request(server+'/slow'),timeout=.1)
    assert time.monotonic()-started<.8
    req=urllib.request.Request(server+'/ok',headers={'Authorization':'Bearer secret-value\r\ninvalid'})
    with pytest.raises(outbound.OutboundPolicyError) as e:outbound.open_request(req)
    assert 'secret-value' not in str(e.value)


def test_dns_pin_preserves_host_without_second_lookup(server,monkeypatch):
    port=int(server.rsplit(':',1)[1]);monkeypatch.setenv('MINISIEM_OUTBOUND_ALLOWLIST',f'http://service.example:{port}')
    original=socket.getaddrinfo;seen=[]
    def resolve(host,port,*a,**k):
        seen.append(host)
        assert host in {'service.example','127.0.0.1'}
        return original('127.0.0.1' if host=='service.example' else host,port,*a,**k)
    monkeypatch.setattr(socket,'getaddrinfo',resolve)
    with outbound.open_request(urllib.request.Request(f'http://service.example:{port}/ok')) as r:assert r.read()==b'x'*100
    assert seen.count('service.example')==1 and Handler.calls[0][1]['Host']==f'service.example:{port}'


def test_tls_context_is_verified_and_capacity_is_bounded(monkeypatch):
    seen={}
    class TLS:
        def __init__(self,host,port,*,timeout,context):seen.update(host=host,context=context)
        def connect(self):raise ssl.SSLCertVerificationError('synthetic untrusted certificate')
        def close(self):pass
    monkeypatch.setattr(outbound,'resolve_destination',lambda *a,**k:(('https','service.example',443),['1.1.1.1']))
    monkeypatch.setattr(outbound.http.client,'HTTPSConnection',TLS)
    with pytest.raises(urllib.error.URLError):outbound.open_request(urllib.request.Request('https://service.example/'))
    assert seen['host']=='service.example' and seen['context'].check_hostname and seen['context'].verify_mode==ssl.CERT_REQUIRED
    gate=threading.BoundedSemaphore(1);gate.acquire();monkeypatch.setattr(outbound,'_SLOTS',gate)
    with pytest.raises(outbound.OutboundPolicyError,match='capacity'):outbound.open_request(urllib.request.Request('https://unused.example/'))


def test_local_llm_defaults_and_worker_preview_compatibility(server,monkeypatch):
    import workers
    assert workers._http(server+'/ok',max_bytes=16)==(200,'x'*16)
    assert workers._http(server+'/ok',max_bytes=None)==(200,'x'*100)
    monkeypatch.delenv('MINISIEM_OUTBOUND_ALLOWLIST',raising=False)
    assert outbound.resolve_destination('http://127.0.0.1:11434/v1',purpose='ai_local')[1]==['127.0.0.1']
    with pytest.raises(outbound.OutboundPolicyError):outbound.resolve_destination('http://127.0.0.1:8080/',purpose='ai_local')


@pytest.mark.parametrize('phase,url',[('token','https://evil.example/token'),
    ('whoami','https://api.central.sophos.com.evil.example/whoami/v1'),
    ('events','https://api-us02.central.sophos.com.evil.example/siem/v1/events')])
def test_sophos_discovery_cannot_send_credentials_outside_provider(monkeypatch,phase,url):
    import api_poller
    worker=api_poller._PollerThread(1,SimpleNamespace(get_row=lambda _: {'auth_scheme':'oauth2_sophos'}))
    monkeypatch.setattr(outbound,'open_request',lambda *a,**k:pytest.fail('unapproved destination connected'))
    with pytest.raises(outbound.OutboundPolicyError):worker._http_json(urllib.request.Request(url),phase)


def test_sophos_cached_token_expiry_discovery_headers_and_cursor(monkeypatch):
    import api_poller
    now=[2_000_000_000.0];monkeypatch.setattr(api_poller.time,'time',lambda:now[0])
    row={'auth_scheme':'oauth2_sophos','client_id':'synthetic-client','scope':'token','cursor':'saved-cursor',
         'token_url':'https://id.sophos.com/api/v2/oauth2/token','whoami_url':'https://api.central.sophos.com/whoami/v1','events_url':'/siem/v1/events'}
    worker=api_poller._PollerThread(1,SimpleNamespace(get_row=lambda _:row,resolve_secret=lambda _:'synthetic-secret'))
    calls=[]
    def send(req,**kwargs):
        calls.append(req)
        if 'oauth2/token' in req.full_url:data={'access_token':'synthetic-jwt'}
        elif 'whoami/v1' in req.full_url:data={'id':'tenant','idType':'tenant','apiHosts':{'dataRegion':'https://api-us02.central.sophos.com'}}
        else:data={'items':[{'id':'event'}],'next_cursor':'next-cursor'}
        return outbound.Response(json.dumps(data).encode(),200,{})
    monkeypatch.setattr(outbound,'open_request',send)
    assert worker._poll_once(row)==([{'id':'event'}],'next-cursor') and len(calls)==3
    assert {k.lower():v for k,v in calls[1].header_items()}=={'authorization':'Bearer synthetic-jwt'}
    assert calls[2].headers['X-tenant-id']=='tenant' and calls[2].full_url.endswith('/siem/v1/events?cursor=saved-cursor')
    worker._poll_once(row);assert len(calls)==4
    now[0]+=3600;worker._poll_once(row);assert len(calls)==7
    assert row['cursor']=='saved-cursor'
