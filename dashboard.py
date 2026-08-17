#!/usr/bin/env python3
"""
mini-SIEM dashboard
====================
Read-only web UI over the SQLite database populated by listener.py.
Pages:
  /            live log search + alert feed
  /correlate   on-demand correlation queries + playbook library
  /setup       syslog forwarding configuration
  /ai          AI SOC analyst (local LLM) — triage + log Q&A

Usage:
    python3 dashboard.py --db siem.db --port 8080
"""

import argparse
import ipaddress
import re
import threading
import time

from flask import Flask, jsonify, render_template, request, session, redirect, url_for

import severity as severity_mod
import db as dbmod
import auth

import ai_soc
import ai_worker
import health as health_mod
from correlations import PLAYBOOKS, get_playbook, run_correlation

app = Flask(__name__)
# --- session cookie hardening ---
# HttpOnly: JS can't read the session cookie (XSS can't steal it).
# SameSite=Lax: mitigates CSRF on state-changing navigations.
# Secure is opt-in via env because many deploys front this with a TLS
# terminator or run on a trusted segment over plain HTTP; forcing Secure
# there would silently break login. Set MINISIEM_COOKIE_SECURE=1 when the
# dashboard itself is reached over HTTPS.
import os as _os
import secrets as _secrets
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_os.environ.get("MINISIEM_COOKIE_SECURE", "") == "1",
)


# Browser CSRF protection. MINISIEM_ALLOWED_ORIGINS accepts a comma-separated
# allowlist; the singular spelling is retained for the common one-origin case.
# When no allowlist is configured the per-session token is still mandatory.
_CSRF_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_EXEMPT_ENDPOINTS = {
    "do_login",       # no authenticated session exists yet
    "saml_acs",       # legitimate cross-site POST from the identity provider
    "api_ingest",     # machine-to-machine endpoint authenticated by API key
}


def _allowed_origins():
    raw = (_os.environ.get("MINISIEM_ALLOWED_ORIGINS")
           or _os.environ.get("MINISIEM_ALLOWED_ORIGIN") or "")
    return {v.strip().rstrip("/") for v in raw.split(",") if v.strip()}


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = _secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def _csrf_template_context():
    return {"csrf_token": _csrf_token}


@app.before_request
def _csrf_guard():
    """Protect state-changing requests authenticated by a browser session."""
    if request.method not in _CSRF_UNSAFE_METHODS:
        return None
    if (request.endpoint or "") in _CSRF_EXEMPT_ENDPOINTS:
        return None
    if not auth.current_user():
        return None

    allowed = _allowed_origins()
    origin = (request.headers.get("Origin") or "").rstrip("/")
    if allowed and (not origin or origin not in allowed):
        return jsonify({"error": "invalid request origin"}), 403

    supplied = (request.headers.get("X-CSRF-Token")
                or request.form.get("csrf_token") or "")
    expected = session.get("csrf_token") or ""
    if not supplied or not expected or not _secrets.compare_digest(supplied, expected):
        return jsonify({"error": "invalid or missing CSRF token"}), 403
    return None


# Lightweight in-process login throttling. This deliberately avoids permanent
# account lockouts (which are easy to weaponize as a denial of service) and DB
# writes on every attempt. Counters reset when the dashboard restarts.
_LOGIN_PAIR_LIMIT = (5, 300)    # failures per (source IP, username), window s
_LOGIN_IP_LIMIT = (20, 600)     # failures per source IP, window s
_LOGIN_FAILURES_BY_PAIR = {}
_LOGIN_FAILURES_BY_IP = {}
_LOGIN_LIMIT_LOCK = threading.Lock()


def _login_source_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",", 1)[0].strip() if forwarded
            else (request.remote_addr or "unknown"))


def _prune_login_failures(store, key, now, window):
    recent = [ts for ts in store.get(key, ()) if now - ts < window]
    if recent:
        store[key] = recent
    else:
        store.pop(key, None)
    return recent


def _login_retry_after(source_ip, username):
    now = time.monotonic()
    pair_key = (source_ip, username.lower())
    with _LOGIN_LIMIT_LOCK:
        pair = _prune_login_failures(
            _LOGIN_FAILURES_BY_PAIR, pair_key, now, _LOGIN_PAIR_LIMIT[1])
        ip_attempts = _prune_login_failures(
            _LOGIN_FAILURES_BY_IP, source_ip, now, _LOGIN_IP_LIMIT[1])
        waits = []
        if len(pair) >= _LOGIN_PAIR_LIMIT[0]:
            waits.append(_LOGIN_PAIR_LIMIT[1] - (now - pair[0]))
        if len(ip_attempts) >= _LOGIN_IP_LIMIT[0]:
            waits.append(_LOGIN_IP_LIMIT[1] - (now - ip_attempts[0]))
    return max(1, int(max(waits)) + 1) if waits else 0


def _record_login_failure(source_ip, username):
    now = time.monotonic()
    pair_key = (source_ip, username.lower())
    with _LOGIN_LIMIT_LOCK:
        pair = _prune_login_failures(
            _LOGIN_FAILURES_BY_PAIR, pair_key, now, _LOGIN_PAIR_LIMIT[1])
        pair.append(now)
        _LOGIN_FAILURES_BY_PAIR[pair_key] = pair
        ip_attempts = _prune_login_failures(
            _LOGIN_FAILURES_BY_IP, source_ip, now, _LOGIN_IP_LIMIT[1])
        ip_attempts.append(now)
        _LOGIN_FAILURES_BY_IP[source_ip] = ip_attempts


def _clear_login_pair(source_ip, username):
    with _LOGIN_LIMIT_LOCK:
        _LOGIN_FAILURES_BY_PAIR.pop((source_ip, username.lower()), None)


@app.after_request
def _security_headers(resp):
    # Defensive response headers. Kept conservative so they don't break the
    # dashboard's own inline scripts/styles: a report-only-friendly CSP would
    # need nonces, so we set the high-value, low-risk headers here.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    # A permissive CSP that still blocks external script injection / framing.
    # 'unsafe-inline' is required because the UI uses inline handlers; it still
    # stops loading script from other origins, which is the main XSS vector.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'")
    return resp

DB_PATH = "siem.db"          # sqlite fallback (back-compat / tests)
DB_CONFIG = None             # set in main(); when None we derive from DB_PATH
AUTH_CONFIG = None           # set by init_auth()
_oauth = None                # Authlib registry, lazily built if oauth enabled


def _db_config():
    return DB_CONFIG if DB_CONFIG is not None else dbmod.config_from_path(DB_PATH)


def admin_required(fn):
    """Guard: only 'admin' role may perform this action. Analysts and
    viewers get 403. SSO users default to admin (see auth.current_role)."""
    from functools import wraps

    @wraps(fn)
    def _wrap(*args, **kwargs):
        if auth.current_role() != "admin":
            audit("permission_denied", target=request.endpoint or request.path,
                  detail=f"role={auth.current_role()}")
            return jsonify({"error": "administrator role required for this action"}), 403
        return fn(*args, **kwargs)
    return _wrap


def get_conn():
    return dbmod.connect(_db_config())


# --- HTTP log ingest -------------------------------------------------------
# siem.py injects the listener's on_message + storage so API-received logs
# flow through the exact same pipeline (parse->store->rules->ioc->fields->
# forward). If no hook is set (dashboard running standalone), the API
# receiver falls back to a direct insert with no rule/ioc processing.
_INGEST_HOOK = None
_INGEST_STORAGE = None


def set_ingest_hook(on_message, storage):
    global _INGEST_HOOK, _INGEST_STORAGE
    _INGEST_HOOK = on_message
    _INGEST_STORAGE = storage


def _ingest_raw(raw_line: str, source_ip: str):
    """Push one raw syslog-format line through the pipeline."""
    if _INGEST_HOOK is not None:
        _INGEST_HOOK(raw_line, source_ip)
        return True
    try:
        import listener as _listener
        import normalize as _normalize
        ev = _listener.parse_syslog(raw_line, source_ip)
        conn = get_conn()
        cur = conn.execute(
            """INSERT INTO logs (received_at, source_ip, peer_ip, format, priority, facility,
               severity, device_timestamp, hostname, destination, app_name, proc_id, msg_id, message, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev["received_at"], ev["source_ip"], ev.get("peer_ip", ""), ev["format"], ev["priority"],
             ev["facility"], ev["severity"], ev["device_timestamp"], ev["hostname"],
             ev.get("destination", ""),
             ev["app_name"], ev["proc_id"], ev["msg_id"], ev["message"], ev["raw"]))
        log_id = cur.lastrowid
        # extract searchable fields (the listener's socket path does this via
        # FieldIndexer; poller/API events come through here, so do it too or
        # they'd have columns but no searchable fields).
        try:
            fields = _normalize.extract_fields(ev.get("message"), [],
                                               json_obj=ev.get("_json"))
            if fields:
                _normalize.write_fields(conn, log_id, fields)
        except Exception:
            pass
        conn.commit(); conn.close()
        return True
    except Exception:
        return False


def _json_to_syslog_line(obj: dict) -> str:
    """Turn a posted JSON log object into an RFC3164-ish syslog line the
    existing parser understands. Recognized optional keys: severity/level,
    hostname/host, app/app_name/program, message/msg. Unknown scalar keys are
    appended as key=value so field extraction can pick them up."""
    from datetime import datetime
    SEV = {"emergency":0,"alert":1,"critical":2,"error":3,"err":3,"warning":4,
           "warn":4,"notice":5,"informational":6,"info":6,"debug":7}
    sev_name = str(obj.get("severity") or obj.get("level") or "info").lower()
    sev = SEV.get(sev_name, 6)
    pri = 16 * 8 + sev  # local0
    host = str(obj.get("hostname") or obj.get("host") or "-")
    app = str(obj.get("app") or obj.get("app_name") or obj.get("program") or "api")
    msg = obj.get("message") or obj.get("msg") or ""
    ts = datetime.now().strftime("%b %e %H:%M:%S")
    known = {"severity","level","hostname","host","app","app_name","program","message","msg"}
    extras = []
    for k, v in obj.items():
        if k in known:
            continue
        if isinstance(v, (str, int, float, bool)):
            sval = str(v)
            if " " in sval or "=" in sval:
                sval = '"' + sval.replace('"', "'") + '"'
            extras.append(f"{k}={sval}")
    body = str(msg)
    if extras:
        body = (body + " " if body else "") + " ".join(extras)
    return f"<{pri}>{ts} {host} {app}: {body}"


def audit(action: str, target: str = "", detail: str = "", username: str = None):
    """Record an admin/user action in the SIEM's own audit trail.
    Best-effort: auditing must never break the action being audited."""
    from datetime import datetime, timezone
    try:
        who = username if username is not None else (auth.current_user() or "anonymous")
        ip = request.remote_addr if request else ""
        conn = get_conn()
        conn.execute(
            "INSERT INTO audit_log (at, username, source_ip, action, target, detail) "
            "VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), who, ip, action,
             str(target)[:200], str(detail)[:500]))
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[audit] write failed ({action}): {exc}")


def init_auth(auth_config_path=None):
    """Load auth config, ensure schema + default admin, set the session
    secret, install the request guard, and build OAuth if enabled. Call
    once at startup (main) — and safe to call in tests."""
    global AUTH_CONFIG, _oauth
    AUTH_CONFIG = auth.load_auth_config(auth_config_path)
    dbmod.initialize(_db_config())
    conn = get_conn()
    auth.seed_default_admin(conn)
    explicit = AUTH_CONFIG.get("session_secret") or ""
    app.secret_key = explicit if explicit else auth.get_or_create_secret(conn)
    conn.close()
    auth.set_conn_factory(get_conn)
    auth.make_guard(app)
    if AUTH_CONFIG.get("oauth", {}).get("enabled"):
        try:
            _oauth = auth.build_oauth(app, AUTH_CONFIG)
        except RuntimeError as exc:
            print(f"[auth] OAuth not initialized: {exc}")
            _oauth = None
    return AUTH_CONFIG


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/correlate")
def correlate_page():
    return render_template("correlate.html")


@app.route("/setup")
def setup_page():
    return render_template("setup.html")


@app.route("/ai")
def ai_page():
    return render_template("ai.html")


@app.route("/health")
def health_page():
    return render_template("health.html")


@app.route("/threatintel")
def threatintel_page():
    return render_template("threatintel.html")


@app.route("/help")
def help_page():
    return render_template("help.html")


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

@app.route("/audit")
def audit_page():
    return render_template("audit.html")


@app.route("/api/audit")
def api_audit():
    username = (request.args.get("username") or "").strip()
    action = (request.args.get("action") or "").strip()
    q = (request.args.get("q") or "").strip()
    limit = min(int(request.args.get("limit", 200)), 2000)
    clauses, params = [], []
    if username:
        clauses.append("username = ?"); params.append(username)
    if action:
        clauses.append("action = ?"); params.append(action)
    if q:
        clauses.append("(target LIKE ? OR detail LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?",
        params + [limit]).fetchall()]
    actions = [r["action"] for r in conn.execute(
        "SELECT DISTINCT action FROM audit_log ORDER BY action").fetchall()]
    users = [r["username"] for r in conn.execute(
        "SELECT DISTINCT username FROM audit_log ORDER BY username").fetchall()]
    conn.close()
    return jsonify({"entries": rows, "actions": actions, "users": users})


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET"])
def login():
    if auth.current_user():
        return redirect(url_for("index"))
    ac = AUTH_CONFIG or auth.load_auth_config()
    return render_template(
        "login.html",
        local_enabled=ac.get("local_auth", {}).get("enabled", True),
        oauth_enabled=bool(ac.get("oauth", {}).get("enabled")) and _oauth is not None,
        oauth_name=ac.get("oauth", {}).get("provider_name", "SSO"),
        saml_enabled=bool(ac.get("saml", {}).get("enabled")),
        error=request.args.get("error", ""),
        next=request.args.get("next", "/"),
    )


@app.route("/login", methods=["POST"])
def do_login():
    ac = AUTH_CONFIG or auth.load_auth_config()
    if not ac.get("local_auth", {}).get("enabled", True):
        return redirect(url_for("login", error="Local login is disabled."))
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    source_ip = _login_source_ip()
    retry_after = _login_retry_after(source_ip, username)
    if retry_after:
        audit("login_rate_limited", target=username,
              detail=f"source={source_ip} retry_after={retry_after}s",
              username=username or "unknown")
        return ("Too many login attempts. Try again later.", 429,
                {"Retry-After": str(retry_after)})
    conn = get_conn()
    user = auth.verify_local(conn, username, password)
    conn.close()
    if not user:
        _record_login_failure(source_ip, username)
        audit("login_failed", target=username, detail="local login rejected", username=username or "unknown")
        return redirect(url_for("login", error="Invalid username or password."))
    _clear_login_pair(source_ip, username)
    auth.login_user(username, "local", must_change=bool(user["must_change_password"]),
                    role=(user["role"] if user["role"] else "viewer"))
    audit("login_success", target=username, detail="local login")
    nxt = request.form.get("next") or "/"
    return redirect(nxt if nxt.startswith("/") else "/")


@app.route("/logout")
def logout():
    audit("logout")
    auth.logout_user()
    return redirect(url_for("login"))


@app.route("/auth/change-password", methods=["GET"])
def change_password():
    if not auth.current_user():
        return redirect(url_for("login"))
    return render_template("change_password.html",
                           forced=bool(session.get("must_change")),
                           error=request.args.get("error", ""))


@app.route("/auth/change-password", methods=["POST"])
def do_change_password():
    if not auth.current_user():
        return redirect(url_for("login"))
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    conn = get_conn()
    user = auth.verify_local(conn, auth.current_user(), current)
    if not user:
        conn.close()
        return redirect(url_for("change_password", error="Current password is incorrect."))
    if len(new) < 8:
        conn.close()
        return redirect(url_for("change_password", error="New password must be at least 8 characters."))
    if new != confirm:
        conn.close()
        return redirect(url_for("change_password", error="New passwords do not match."))
    if new == auth.DEFAULT_ADMIN_PASS:
        conn.close()
        return redirect(url_for("change_password", error="Choose a password other than the default."))
    auth.set_password(conn, auth.current_user(), new)
    conn.close()
    session["must_change"] = False
    audit("password_changed", detail="via change-password page")
    return redirect(url_for("index"))


@app.route("/auth/oauth/login")
def oauth_login():
    if not _oauth:
        return redirect(url_for("login", error="OAuth is not configured."))
    redirect_uri = url_for("oauth_callback", _external=True)
    return _oauth.sso.authorize_redirect(redirect_uri)


@app.route("/auth/oauth/callback")
def oauth_callback():
    if not _oauth:
        return redirect(url_for("login", error="OAuth is not configured."))
    try:
        token = _oauth.sso.authorize_access_token()
        userinfo = token.get("userinfo") or _oauth.sso.userinfo()
    except Exception as exc:
        return redirect(url_for("login", error=f"OAuth failed: {type(exc).__name__}"))
    username = auth.oauth_identity(token, userinfo)
    conn = get_conn()
    auth.upsert_sso_user(conn, username, "oauth")
    conn.close()
    auth.login_user(username, "oauth", must_change=False)
    audit("login_success", target=username, detail="OAuth SSO")
    return redirect(url_for("index"))


@app.route("/auth/saml/login")
def saml_login():
    ac = AUTH_CONFIG or auth.load_auth_config()
    try:
        saml_auth = auth.build_saml_auth(request, ac)
    except RuntimeError as exc:
        return redirect(url_for("login", error=str(exc)))
    return redirect(saml_auth.login())


@app.route("/auth/saml/acs", methods=["POST"])
def saml_acs():
    ac = AUTH_CONFIG or auth.load_auth_config()
    try:
        saml_auth = auth.build_saml_auth(request, ac)
        saml_auth.process_response()
        errors = saml_auth.get_errors()
        if errors or not saml_auth.is_authenticated():
            return redirect(url_for("login", error="SAML authentication failed."))
        username = saml_auth.get_nameid()
    except RuntimeError as exc:
        return redirect(url_for("login", error=str(exc)))
    except Exception as exc:
        return redirect(url_for("login", error=f"SAML error: {type(exc).__name__}"))
    conn = get_conn()
    auth.upsert_sso_user(conn, username, "saml")
    conn.close()
    auth.login_user(username, "saml", must_change=False)
    audit("login_success", target=username, detail="SAML SSO")
    return redirect(url_for("index"))


@app.route("/auth/saml/metadata")
def saml_metadata():
    ac = AUTH_CONFIG or auth.load_auth_config()
    try:
        saml_auth = auth.build_saml_auth(request, ac)
        settings = saml_auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if errors:
            return jsonify({"error": errors}), 500
        return app.response_class(metadata, mimetype="text/xml")
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/whoami")
def whoami():
    return jsonify({"user": auth.current_user(), "source": session.get("auth_source"),
                    "role": auth.current_role()})


AI_DEFAULTS = {
    "ai_enabled": "false",                        # master switch, off until you build the box
    "ai_mode": "local",                           # "local" or "external" (uses a token, sends data off-site)
    "ai_base_url": "http://localhost:11434/v1",   # Ollama default
    "ai_model": "qwen2.5:7b",
    "ai_api_key": "",
    "ai_auto_triage": "true",                     # auto-send alerts to the LLM when AI is on
    "ai_auto_triage_min_severity": "",            # "" = all alerts; else e.g. "warning"
    "ai_auto_triage_max_age_hours": "0",          # 0 = no limit; else skip alerts older than N hours
    "ai_system_prompt": "",                       # "" = use built-in SOC analyst prompt
    "ai_user_template": "",                        # "" = default framing; supports {evidence} {rule_name} {severity} {source_ip} {description}
    "ai_max_tokens": "900",                        # max output tokens per response
}


def ensure_schema():
    """Create all tables/indexes if missing, using the active backend's
    dialect. Idempotent; safe to call from any endpoint."""
    dbmod.initialize(_db_config())


def ensure_app_config():
    ensure_schema()


def get_ai_config():
    ensure_app_config()
    conn = get_conn()
    rows = {r["key"]: r["value"] for r in
            conn.execute("SELECT key, value FROM app_config").fetchall()}
    conn.close()
    cfg = dict(AI_DEFAULTS)
    for k in AI_DEFAULTS:
        if k in rows and rows[k] is not None:
            cfg[k] = rows[k]
    return cfg


def save_ai_config(updates: dict):
    ensure_app_config()
    conn = get_conn()
    for k, v in updates.items():
        if k in AI_DEFAULTS:
            conn.execute(
                "INSERT INTO app_config(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
    conn.commit()
    conn.close()


def _llm_from_config():
    cfg = get_ai_config()
    return ai_soc.LLMClient(cfg["ai_base_url"], cfg["ai_model"], cfg["ai_api_key"])


_triage_worker = None


def _triage_settings():
    cfg = get_ai_config()
    return {
        "enabled": cfg["ai_enabled"] == "true",
        "auto_triage": cfg.get("ai_auto_triage", "true") == "true",
        "min_severity": cfg.get("ai_auto_triage_min_severity", ""),
        "max_age_hours": int(cfg.get("ai_auto_triage_max_age_hours", "0") or 0),
        "system_prompt": cfg.get("ai_system_prompt", ""),
        "user_template": cfg.get("ai_user_template", ""),
        "max_tokens": int(cfg.get("ai_max_tokens", "900") or 900),
        "llm": _llm_from_config(),
    }


def start_triage_worker():
    """Start the background auto-triage worker (idempotent)."""
    global _triage_worker
    if _triage_worker is None:
        _triage_worker = ai_worker.TriageWorker(get_conn, _triage_settings)
    _triage_worker.start()
    return _triage_worker


_automation_started = False


def start_automation_workers():
    """Start report scheduler, ticket dispatcher, and feed refresher."""
    global _automation_started
    if _automation_started:
        return
    import workers
    workers.ReportScheduler(get_conn, lambda: cfg_get("report_schedule", "off")).start()
    workers.TicketWorker(get_conn, get_ticket_settings).start()
    workers.FeedRefresher(get_conn, resolve_key_fn=_resolve_feed_key).start()
    _automation_started = True


def ensure_forwarders_table():
    ensure_schema()


def _fts_token(needle):
    """Turn a user search needle into a safe FTS5 token expression.
    Multi-word needles become a quoted phrase; single words become a prefix
    match (word*). Strips FTS syntax characters to avoid injection/parse
    errors. Returns '' if nothing usable remains."""
    if not needle:
        return ""
    # keep alphanumerics, spaces, dots, hyphens, underscores; drop FTS
    # operators/quotes that would break the MATCH grammar
    cleaned = re.sub(r'[^\w\s.\-]', ' ', needle).strip()
    if not cleaned:
        return ""
    parts = cleaned.split()
    if len(parts) == 1:
        # single word -> prefix match so "fort" finds "fortigate"
        return f'"{parts[0]}"*'
    # multiple words -> exact phrase (quoted), no prefix on phrases
    return '"' + " ".join(parts) + '"'


def _fts_build_match(include, exclude):
    """Assemble an FTS5 MATCH expression from include/exclude token lists.
    include terms are AND-ed; exclude terms are NOT-ed. FTS5 requires at
    least one positive term for a NOT to be meaningful, so a query that is
    ONLY exclusions returns '' (caller falls back to LIKE)."""
    if not include and not exclude:
        return ""
    if include and not exclude:
        return " AND ".join(include)
    if include and exclude:
        return " AND ".join(include) + " NOT " + " NOT ".join(exclude)
    # only exclusions — FTS can't express "everything except X" alone
    return ""


def _subnet_clause(column, term):
    """If `term` looks like a subnet (CIDR like 192.168.1.0/24, or a bare
    dotted prefix like 192.168.1.0 / 192.168.1. / 192.168.), return
    (sql_clause, params) that matches any IP inside it. Otherwise return None.

    /8, /16, /24 use anchored octet-boundary LIKE (index-friendly, and avoids
    the '192.168.1' also matching '192.168.10' string-prefix bug). Arbitrary
    CIDR masks (/25, /23, etc.) fall back to an integer range on IPs that
    parse, which is correct but scans.
    """
    t = term.strip()
    # explicit CIDR
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return None
        prefix = net.prefixlen
        if prefix in (8, 16, 24) and net.version == 4:
            octets = str(net.network_address).split(".")
            keep = prefix // 8
            base = ".".join(octets[:keep]) + "."
            return (f"{column} LIKE ?", [base + "%"])
        # non-octet CIDR: integer range over parseable IPv4 in the column
        first = int(net.network_address)
        last = int(net.broadcast_address)
        # SQLite can't parse IPs; do it by matching the /24-ish prefix broadly
        # then it's still correct because we bound by the LIKE of the first
        # three octets when possible. Simplest correct fallback: octet prefix
        # of the common part, then Python can't post-filter here — so we use a
        # broad LIKE on the shared leading octets.
        shared = str(net.network_address).split(".")
        # find how many leading octets are fixed across the range
        fo = str(ipaddress.ip_address(first)).split(".")
        lo = str(ipaddress.ip_address(last)).split(".")
        common = []
        for a, b in zip(fo, lo):
            if a == b:
                common.append(a)
            else:
                break
        if common:
            return (f"{column} LIKE ?", [".".join(common) + ".%"])
        return None
    # bare dotted forms treated as octet-boundary subnets
    # 192.168.1.0 / 192.168.1. / 192.168. / 192.168
    m = t.rstrip(".")
    parts = m.split(".")
    if 1 <= len(parts) <= 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        # e.g. "192.168.1" -> match "192.168.1." prefix (a /24)
        return (f"{column} LIKE ?", [".".join(parts) + ".%"])
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        # a full IP ending in .0 is commonly "the whole /24"
        if parts[3] == "0":
            return (f"{column} LIKE ?", [".".join(parts[:3]) + ".%"])
    return None


def _concept_clause(column, concept, term, negate):
    """Build the WHERE clause for one search term against a canonical
    concept (source / host / destination): matches the base COLUMN (which
    is already correct for most sources) OR any of the concept's configured
    alias field names in log_fields (the safety net for sources that use a
    different field name for the same idea, e.g. Sophos's endpoint_ip for
    "source"). Resolved fresh per request from get_search_aliases(), so
    editing the config applies to historical data immediately — nothing to
    reindex.
    Returns (sql, params); sql is already negated (NOT ...) if requested.
    """
    aliases = get_search_aliases().get(concept) or []
    subnet = _subnet_clause(column, term)
    if subnet:
        col_sql, col_params = subnet
        needle = None  # subnet clause already encodes the match
    else:
        col_sql, col_params = f"{column} LIKE ?", [f"%{term}%"]

    if aliases:
        ph = ",".join("?" * len(aliases))
        if subnet:
            # same subnet-boundary LIKE pattern, applied to the alias value
            alias_pattern = col_params[-1]  # the LIKE pattern _subnet_clause built
            alias_sql = (f"EXISTS (SELECT 1 FROM log_fields hf WHERE hf.log_id = l.id "
                         f"AND hf.field IN ({ph}) AND hf.value LIKE ?)")
            alias_params = list(aliases) + [alias_pattern]
        else:
            alias_sql = (f"EXISTS (SELECT 1 FROM log_fields hf WHERE hf.log_id = l.id "
                         f"AND hf.field IN ({ph}) AND LOWER(hf.value) LIKE ?)")
            alias_params = list(aliases) + [f"%{term.lower()}%"]
        sql = f"({col_sql} OR {alias_sql})"
        params = col_params + alias_params
    else:
        sql = f"({col_sql})"
        params = col_params

    return (f"NOT {sql}" if negate else sql), params



def _build_log_query(args, select_cols):
    """Shared WHERE builder for log search + export. Supports q, source_ip,
    hostname, severity (synonym-aware), time range (from/to ISO), and ids."""
    q = args.get("q", "").strip()
    source_ip = args.get("source_ip", "").strip()
    hostname = args.get("hostname", "").strip()
    destination = args.get("destination", "").strip()
    severity = args.get("severity", "").strip()
    time_from = args.get("from", "").strip()
    time_to = args.get("to", "").strip()
    ids = args.get("ids", "").strip()

    clauses, params = [], []
    if ids:
        id_list = [int(i) for i in ids.split(",") if i.strip().isdigit()][:500]
        if id_list:
            clauses.append(f"id IN ({','.join('?' * len(id_list))})")
            params.extend(id_list)
    if q:
        # Message search via FTS5 (fast, indexed) instead of leading-wildcard
        # LIKE scans. Preserves the existing syntax:
        #   error                 -> message contains the word "error"
        #   !tasklist             -> excludes "tasklist"
        #   error, !tasklist      -> has "error" AND not "tasklist"
        # Terms are comma-separated. Each term becomes a prefix token match
        # (term*) so "fort" still finds "fortigate"; excluded terms become
        # FTS NOT clauses. If a term can't be expressed in FTS (empty after
        # cleaning), it's skipped. The whole thing is one MATCH subquery.
        include, exclude = [], []
        terms = [t.strip() for t in q.split(",")] if "," in q else [q.strip()]
        for term in terms:
            if not term:
                continue
            neg = term.startswith("!=") or term.startswith("!")
            needle = (term[2:] if term.startswith("!=") else term[1:]).strip() if neg else term
            tok = _fts_token(needle)
            if not tok:
                continue
            (exclude if neg else include).append(tok)
        match_expr = _fts_build_match(include, exclude)
        if match_expr:
            clauses.append("id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH ?)")
            params.append(match_expr)
        else:
            # nothing expressible in FTS (e.g. only punctuation) — fall back to
            # a LIKE on the single term so the search still does something.
            for term in terms:
                t = term.strip()
                if not t:
                    continue
                neg = t.startswith("!=") or t.startswith("!")
                needle = (t[2:] if t.startswith("!=") else t[1:]).strip() if neg else t
                if needle:
                    clauses.append("message NOT LIKE ?" if neg else "message LIKE ?")
                    params.append(f"%{needle}%")
    if source_ip:
        # Supports exclusion (!term), partial match, subnet (CIDR or dotted
        # prefix like 192.168.1.0), comma-separated:
        #   sophos-central     -> source contains it
        #   192.168.1.0/24     -> any IP in that subnet
        #   192.168.1.0        -> treated as the /24
        #   !10.0.0.0/8        -> exclude that subnet
        # Also matches the "source" concept's configured alias fields (Setup
        # -> Search field aliases), so an IP that lives in a different field
        # per source — Fortigate's src= vs Sophos's endpoint_ip — is
        # findable with ONE search regardless of which source it came from.
        for term in ([t.strip() for t in source_ip.split(",")] if "," in source_ip else [source_ip]):
            if not term:
                continue
            negate = term.startswith("!=") or term.startswith("!")
            needle = (term[2:] if term.startswith("!=") else term[1:]).strip() if negate else term
            if not needle:
                continue
            sql, sp = _concept_clause("source_ip", "source", needle, negate)
            clauses.append(sql)
            params.extend(sp)
    if hostname:
        # Same inclusion/exclusion/partial/subnet semantics as source, and
        # the same alias-fallback behavior via the "host" concept aliases.
        for term in ([t.strip() for t in hostname.split(",")] if "," in hostname else [hostname]):
            if not term:
                continue
            negate = term.startswith("!=") or term.startswith("!")
            needle = (term[2:] if term.startswith("!=") else term[1:]).strip() if negate else term
            if not needle:
                continue
            sql, sp = _concept_clause("hostname", "host", needle, negate)
            clauses.append(sql)
            params.extend(sp)
    if destination:
        # New: Destination previously had a column and a display, but no
        # search box at all. Same semantics as source/host, via the
        # "destination" concept aliases.
        for term in ([t.strip() for t in destination.split(",")] if "," in destination else [destination]):
            if not term:
                continue
            negate = term.startswith("!=") or term.startswith("!")
            needle = (term[2:] if term.startswith("!=") else term[1:]).strip() if negate else term
            if not needle:
                continue
            sql, sp = _concept_clause("destination", "destination", needle, negate)
            clauses.append(sql)
            params.extend(sp)
    if severity:
        # Severity supports operators for richer filtering:
        #   informational        -> exactly that severity (synonym-aware)
        #   !=informational      -> everything EXCEPT that severity
        #   >=warning            -> warning and MORE severe (rank-based)
        #   >warning / <= / <    -> other rank comparisons
        # Rank: emergency(0) most severe .. debug(7) least. ">=warning"
        # means "at least as severe as warning" = rank <= warning's rank.
        SEV_RANK = ("emergency", "alert", "critical", "error", "warning",
                    "notice", "informational", "debug")
        rank_of = {s: i for i, s in enumerate(SEV_RANK)}
        op = "="
        val = severity
        for cand in ("!=", ">=", "<=", ">", "<"):
            if severity.startswith(cand):
                op = cand
                val = severity[len(cand):].strip()
                break
        canon = (severity_mod.synonyms_of(val) or [val.lower()])
        canon_name = canon[0] if canon else val.lower()
        if op == "=":
            clauses.append(f"LOWER(severity) IN ({','.join('?' * len(canon))})")
            params.extend(canon)
        elif op == "!=":
            clauses.append(f"LOWER(severity) NOT IN ({','.join('?' * len(canon))})")
            params.extend(canon)
        elif op in (">=", ">", "<=", "<") and canon_name in rank_of:
            # map the operator on *severity* to an operator on *rank*.
            # more severe = lower rank number, so >= severity => <= rank.
            target = rank_of[canon_name]
            rank_op = {">=": "<=", ">": "<", "<=": ">=", "<": ">"}[op]
            cases = " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEV_RANK))
            clauses.append(f"(CASE LOWER(severity) {cases} ELSE 99 END) {rank_op} ?")
            params.append(target)
    if time_from:
        clauses.append("received_at >= ?")
        params.append(time_from)
    if time_to:
        clauses.append("received_at <= ?")
        params.append(time_to)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    # base-column sort: sort=<col>&dir=asc|desc. Whitelisted to real columns
    # so this can't be used for SQL injection. Extracted-field sort (sort=x_*)
    # is handled separately in _query_logs_extracted and ignored here.
    SORTABLE = {"received_at": "received_at", "source_ip": "source_ip",
                "severity": "severity", "hostname": "hostname",
                "app_name": "app_name", "id": "id"}
    sort = (args.get("sort") or "").strip()
    direction = "ASC" if (args.get("dir") or "").lower() == "asc" else "DESC"
    # severity should sort by actual rank (emergency..debug), not alphabetically
    SEV_RANK = ("emergency", "alert", "critical", "error", "warning",
                "notice", "informational", "debug")
    if sort == "severity":
        cases = " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEV_RANK))
        order = f"ORDER BY CASE LOWER(severity) {cases} ELSE 99 END {direction}, id DESC"
    elif sort in SORTABLE:
        order = f"ORDER BY {SORTABLE[sort]} {direction}, id DESC"
    else:
        order = "ORDER BY id DESC"
    sql = f"SELECT {select_cols} FROM logs l {where} {order}"
    return sql, params


def _extraction_args(args):
    """Parse extracted-field params: fields=user,action ; f_<name>=substr ;
    sort=x_<name> ; dir=asc|desc. Returns (fields, filters, sort, direction)."""
    fields = [c.strip() for c in (args.get("fields") or "").split(",") if c.strip()][:8]
    filters = {}
    for k, v in args.items():
        if k.startswith("f_") and v.strip():
            name = k[2:].strip()
            if name:
                val = v.strip()
                # a leading ! (or !=) means EXCLUDE this field=value.
                negate = False
                if val.startswith("!=") or val.startswith("!"):
                    negate = True
                    val = val[2:].strip() if val.startswith("!=") else val[1:].strip()
                filters[name] = {"needle": val.lower(), "negate": negate}
                if name not in fields:
                    fields.append(name)
    sort = (args.get("sort") or "").strip()
    direction = "desc" if (args.get("dir") or "").lower() == "desc" else "asc"
    return fields, filters, sort, direction


def _query_logs_extracted(args, limit, select_cols, sort_cap=100000):
    """Query logs with extracted-field support via the indexed log_fields
    table (materialized at ingest). Field filters become indexed JOINs;
    sorting fetches (id, value) pairs from the index (capped at sort_cap)
    and orders numerically in-process; display values are batch-fetched
    for just the returned page. No message re-scanning."""
    fields, filters, sort, direction = _extraction_args(args)
    needs = bool(fields or filters or sort.startswith("x_"))

    base_sql, base_params = _build_log_query(args, select_cols)
    conn = get_conn()
    try:
        if not needs:
            rows = [dict(r) for r in conn.execute(
                base_sql + " LIMIT ?", base_params + [limit]).fetchall()]
            return rows

        # base WHERE applies to alias l
        where_part = ""
        if " WHERE " in base_sql:
            where_part = base_sql.split(" WHERE ", 1)[1].split(" ORDER BY ", 1)[0]
        joins, join_params = [], []
        extra_where, extra_params = [], []
        ji = 0
        # fc_op=or combines the POSITIVE field filters (the query-builder
        # chips) with OR instead of the default AND. Negated filters (!term)
        # always stay AND'd in regardless of this mode — "match ANY of these,
        # but exclude that" is a coherent combination; OR-ing an exclusion
        # in would defeat the purpose of excluding it. Default (no fc_op, or
        # any value other than "or") is byte-identical to prior behavior, so
        # every existing saved link/bookmark keeps working unchanged.
        or_mode = (args.get("fc_op") or "").strip().lower() == "or"
        or_group, or_group_params = [], []
        for name, spec in filters.items():
            # tolerate the older shape (plain string) as an include filter
            if isinstance(spec, dict):
                needle, negate = spec.get("needle", ""), spec.get("negate", False)
            else:
                needle, negate = spec, False
            if negate:
                # EXCLUDE: no row for this field matching the value.
                extra_where.append(
                    "NOT EXISTS (SELECT 1 FROM log_fields fx WHERE fx.log_id = l.id "
                    "AND fx.field = ? AND LOWER(fx.value) LIKE ?)")
                extra_params.extend([name, f"%{needle}%"])
            else:
                if or_mode:
                    # kept in a SEPARATE accumulator (not extra_params) because
                    # this clause is only appended to extra_where AFTER the
                    # loop ends (it needs every chip collected first) — if its
                    # params were interleaved into extra_params at loop time,
                    # alongside negate params that DO land in extra_where
                    # immediately, the final param list would be ordered by
                    # "when appended" while the clause list is ordered by
                    # "where appended", desyncing every ? placeholder after
                    # the first negate+OR mix. Appending both the clause and
                    # its params after the loop, together, keeps them aligned.
                    or_group.append(
                        "EXISTS (SELECT 1 FROM log_fields fo WHERE fo.log_id = l.id "
                        "AND fo.field = ? AND LOWER(fo.value) LIKE ?)")
                    or_group_params.extend([name, f"%{needle}%"])
                else:
                    joins.append(
                        f"JOIN log_fields f{ji} ON f{ji}.log_id = l.id "
                        f"AND f{ji}.field = ? AND LOWER(f{ji}.value) LIKE ?")
                    join_params.extend([name, f"%{needle}%"])
                    ji += 1
        if or_group:
            # single positive filter behaves the same whether "AND" or "OR"
            # is selected, so this only changes behavior with 2+ chips.
            extra_where.append("(" + " OR ".join(or_group) + ")")
            extra_params.extend(or_group_params)
        # combine base WHERE with any exclusion clauses
        where_clauses = []
        if where_part:
            where_clauses.append(where_part)
        where_clauses.extend(extra_where)
        combined_where = " AND ".join(where_clauses)

        cols = ", ".join("l." + c.strip() for c in select_cols.split(","))
        sql = f"SELECT {cols} FROM logs l " + " ".join(joins)
        params = list(join_params)
        if combined_where:
            sql += " WHERE " + combined_where
            if where_part:
                params.extend(base_params)
            params.extend(extra_params)

        if sort.startswith("x_"):
            name = sort[2:]
            sv_sql = (f"SELECT l.id AS lid, sv.value AS sval FROM logs l "
                      + " ".join(joins)
                      + " LEFT JOIN log_fields sv ON sv.log_id = l.id AND sv.field = ?")
            sv_params = list(join_params) + [name]
            if combined_where:
                sv_sql += " WHERE " + combined_where
                if where_part:
                    sv_params.extend(base_params)
                sv_params.extend(extra_params)
            sv_sql += " ORDER BY l.id DESC LIMIT ?"
            sv_params.append(sort_cap)
            pairs = [(r["lid"], r["sval"]) for r in conn.execute(sv_sql, sv_params).fetchall()]
            present = [(i, v) for i, v in pairs if v not in (None, "")]
            missing = [i for i, v in pairs if v in (None, "")]
            def key(t):
                try:
                    return (0, float(t[1]), "")
                except (TypeError, ValueError):
                    return (1, 0, str(t[1]).lower())
            present.sort(key=key, reverse=(direction == "desc"))
            ordered_ids = [i for i, _ in present] + missing
            page_ids = ordered_ids[:limit]
            if not page_ids:
                return []
            ph = ",".join("?" * len(page_ids))
            fetched = {r["id"]: dict(r) for r in conn.execute(
                f"SELECT {cols} FROM logs l WHERE l.id IN ({ph})", page_ids).fetchall()}
            rows = [fetched[i] for i in page_ids if i in fetched]
        else:
            # base-column sort (or default) while extracted columns are shown
            SORTABLE = {"received_at", "source_ip", "severity", "hostname",
                        "app_name", "id"}
            if sort in SORTABLE:
                d = "ASC" if direction == "asc" else "DESC"
                sql += f" ORDER BY l.{sort} {d}, l.id DESC LIMIT ?"
            else:
                sql += " ORDER BY l.id DESC LIMIT ?"
            params.append(limit)
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]

        # batch-fetch display values for this page only
        if rows and fields:
            ids = [r["id"] for r in rows]
            ph = ",".join("?" * len(ids))
            fph = ",".join("?" * len(fields))
            vals = {}
            for fr in conn.execute(
                    f"SELECT log_id, field, value FROM log_fields "
                    f"WHERE log_id IN ({ph}) AND field IN ({fph})",
                    ids + fields).fetchall():
                vals.setdefault(fr["log_id"], {})[fr["field"]] = fr["value"]
            for r in rows:
                got = vals.get(r["id"], {})
                r["extracted"] = {f: got.get(f, "") for f in fields}
        elif fields:
            for r in rows:
                r["extracted"] = {f: "" for f in fields}
        return rows
    finally:
        conn.close()


@app.route("/api/logs")
def api_logs():
    limit = min(int(request.args.get("limit", 200)), 1000)
    rows = _query_logs_extracted(
        request.args, limit,
        "id, received_at, source_ip, peer_ip, severity, facility, hostname, destination, app_name, message")
    # Enrich with endpoint_ip (stored as a field, not a base column) so the UI
    # can show it in the Net-source column for sources with no network src=
    # (e.g. Sophos, whose 'source' is the connector name). Batch-fetched for
    # just this page — no per-row queries.
    ids = [r["id"] for r in rows]
    if ids:
        conn = get_conn()
        ph = ",".join("?" * len(ids))
        eip = {r["log_id"]: r["value"] for r in conn.execute(
            f"SELECT log_id, value FROM log_fields "
            f"WHERE field='endpoint_ip' AND log_id IN ({ph})", ids).fetchall()}
        conn.close()
        for r in rows:
            if eip.get(r["id"]):
                r["endpoint_ip"] = eip[r["id"]]
    return jsonify(rows)


@app.route("/api/logs/facets")
def api_logs_facets():
    """Distinct source IPs, hostnames, and destinations for the filter dropdowns."""
    conn = get_conn()
    srcs = [r["source_ip"] for r in conn.execute(
        """SELECT source_ip FROM logs WHERE source_ip IS NOT NULL AND source_ip != ''
           GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 200""").fetchall()]
    hosts = [r["hostname"] for r in conn.execute(
        """SELECT hostname FROM logs WHERE hostname IS NOT NULL AND hostname != ''
           GROUP BY hostname ORDER BY COUNT(*) DESC LIMIT 200""").fetchall()]
    dests = [r["destination"] for r in conn.execute(
        """SELECT destination FROM logs WHERE destination IS NOT NULL AND destination != ''
           GROUP BY destination ORDER BY COUNT(*) DESC LIMIT 200""").fetchall()]
    conn.close()
    return jsonify({"sources": srcs, "hosts": hosts, "destinations": dests})


@app.route("/api/logs/export")
def api_logs_export():
    """Export the currently-filtered logs as CSV or JSON."""
    import csv
    import io
    import json as _json
    fmt = request.args.get("format", "csv").lower()
    limit = min(int(request.args.get("limit", 100000)), 500000)
    rows = _query_logs_extracted(
        request.args, limit,
        "id, received_at, source_ip, severity, facility, hostname, app_name, message, raw",
        sort_cap=500000)
    # flatten extracted fields into x_<name> columns for CSV/JSON
    extra_cols = []
    for r in rows:
        for k, v in (r.pop("extracted", {}) or {}).items():
            col = "x_" + k
            r[col] = v
            if col not in extra_cols:
                extra_cols.append(col)

    stamp = _dt_stamp()
    if fmt == "json":
        payload = _json.dumps(rows, indent=2)
        return app.response_class(
            payload, mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=siem-logs-{stamp}.json"})
    # CSV
    buf = io.StringIO()
    cols = ["id", "received_at", "source_ip", "hostname", "severity",
            "facility", "app_name"] + extra_cols + ["message", "raw"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return app.response_class(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=siem-logs-{stamp}.csv"})


def _dt_stamp():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


@app.route("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 100)), 1000)
    group = request.args.get("group", "").lower() in ("1", "true", "yes")
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()]
    conn.close()
    if not group:
        return jsonify(rows)

    # Display-only grouping by rule_name + source_ip. The rows themselves are
    # untouched in the DB; we just collapse identical ones for the view. Each
    # group carries a representative (newest) alert plus its members and an
    # aggregate AI/ticket status so the badge reflects the whole group.
    groups = {}
    order = []
    for a in rows:
        key = (a.get("rule_name"), a.get("source_ip"))
        g = groups.get(key)
        if g is None:
            g = {
                "group_key": f"{a.get('rule_name')}|{a.get('source_ip')}",
                "rule_name": a.get("rule_name"),
                "source_ip": a.get("source_ip"),
                "severity": a.get("severity"),
                "description": a.get("description"),
                "count": 0,
                "latest": a.get("created_at"),
                "earliest": a.get("created_at"),
                "representative": a,       # newest (rows are DESC)
                "members": [],
                "ai_done": 0, "ai_pending": 0, "ai_error": 0, "ai_skipped": 0,
                "ticketed": 0,
            }
            groups[key] = g
            order.append(key)
        g["count"] += 1
        g["members"].append(a)
        if a.get("created_at") and a["created_at"] < g["earliest"]:
            g["earliest"] = a["created_at"]
        st = (a.get("ai_status") or "pending").lower()
        if st == "done": g["ai_done"] += 1
        elif st == "error": g["ai_error"] += 1
        elif st == "skipped": g["ai_skipped"] += 1
        else: g["ai_pending"] += 1
        if (a.get("ticket_status") or "") == "created":
            g["ticketed"] += 1
    return jsonify({"grouped": True, "groups": [groups[k] for k in order]})


@app.route("/api/stats")
def api_stats():
    """Dashboard stats that answer 'what needs me, what's missing' rather
    than 'what's most frequent'."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(hours=24)).isoformat()
    # A source is "silent" only after 3 days of nothing — long enough to
    # span a Sat/Sun off-work gap without crying wolf every Monday.
    silence_cutoff = (now - timedelta(days=3)).isoformat()
    # ...measured against a 2-week baseline, so a device has room to have
    # logged before the silence window opens.
    baseline_start = (now - timedelta(days=14)).isoformat()

    conn = get_conn()
    total_logs = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

    # Actionable alerts: warning and above (warning/error/critical/alert/
    # emergency), broken down so the Total-alerts card can show the split
    # and act as a shortcut to the ones that matter.
    sev_counts = {}
    for r in conn.execute(
        "SELECT LOWER(severity) s, COUNT(*) c FROM alerts GROUP BY LOWER(severity)"):
        sev_counts[r["s"] or "informational"] = r["c"]
    actionable = sum(sev_counts.get(s, 0) for s in
                     ("warning", "error", "critical", "alert", "emergency"))

    # 1. Needs attention: critical+error alerts in 24h, and how many untriaged
    high = conn.execute(
        """SELECT COUNT(*) c FROM alerts
           WHERE created_at >= ? AND LOWER(severity) IN ('critical','error','alert','emergency')""",
        (day_ago,)).fetchone()["c"]
    untriaged = conn.execute(
        """SELECT COUNT(*) c FROM alerts
           WHERE created_at >= ? AND LOWER(severity) IN ('critical','error','alert','emergency')
             AND (ai_status IS NULL OR ai_status IN ('pending','error'))""",
        (day_ago,)).fetchone()["c"]

    # 2. Silent sources: logged in the past 14 days but nothing for 3 days
    silent = [r["source_ip"] for r in conn.execute(
        """SELECT DISTINCT source_ip FROM logs
           WHERE received_at >= ? AND received_at < ?
             AND source_ip IS NOT NULL AND source_ip != ''
             AND source_ip NOT IN (
                 SELECT DISTINCT source_ip FROM logs WHERE received_at >= ?)
           LIMIT 50""",
        (baseline_start, silence_cutoff, silence_cutoff)).fetchall()]

    # 3. IOC matches in the last 24h
    try:
        ioc_hits = conn.execute(
            "SELECT COUNT(*) c FROM ioc_matches WHERE matched_at >= ?",
            (day_ago,)).fetchone()["c"]
    except Exception:
        ioc_hits = 0

    conn.close()
    return jsonify({
        "total_logs": total_logs,
        "listen_ports": _listen_ports_configured(),
        "total_alerts": total_alerts,
        "alerts_breakdown": {
            "actionable": actionable,
            "critical": sev_counts.get("critical", 0) + sev_counts.get("alert", 0)
                        + sev_counts.get("emergency", 0),
            "error": sev_counts.get("error", 0),
            "warning": sev_counts.get("warning", 0),
        },
        "needs_attention": {"high_24h": high, "untriaged": untriaged},
        "silent_sources": {"count": len(silent), "sources": silent[:10],
                           "silence_days": 3, "baseline_days": 14},
        "ioc_hits_24h": ioc_hits,
    })


# ---------------------------------------------------------------------------
# Correlation endpoints
# ---------------------------------------------------------------------------

@app.route("/api/playbooks")
def api_playbooks():
    # Everything except nothing — the full definitions are useful in the UI
    return jsonify(PLAYBOOKS)


@app.route("/api/playbooks/run", methods=["POST"])
def api_playbooks_run():
    body = request.get_json(force=True, silent=True) or {}
    pb = get_playbook(body.get("id", ""))
    if not pb:
        return jsonify({"error": "unknown playbook id"}), 404

    params = dict(pb["params"])  # copy — never mutate the library entry
    if body.get("window_minutes"):
        params["window_minutes"] = int(body["window_minutes"])
        params.pop("since", None)

    conn = get_conn()
    try:
        result = run_correlation(conn, params)
    except Exception as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 400
    conn.close()
    result["playbook"] = {k: pb[k] for k in
                          ("id", "name", "severity", "description", "response_steps")}
    return jsonify(result)


@app.route("/api/correlate", methods=["POST"])
def api_correlate():
    params = request.get_json(force=True, silent=True) or {}
    allowed_group_by = {"source_ip", "hostname", "app_name", "user"}
    if params.get("group_by") not in allowed_group_by:
        return jsonify({"error": f"group_by must be one of {sorted(allowed_group_by)}"}), 400
    if params.get("distinct_field") and params["distinct_field"] not in allowed_group_by:
        return jsonify({"error": f"distinct_field must be one of {sorted(allowed_group_by)}"}), 400

    conn = get_conn()
    try:
        result = run_correlation(conn, params)
    except Exception as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 400
    conn.close()
    return jsonify(result)


# ---------------------------------------------------------------------------
# Forwarder configuration endpoints (used by /setup)
# ---------------------------------------------------------------------------

VALID_SEVERITIES = {"", "emergency", "alert", "critical", "error",
                    "warning", "notice", "informational", "debug"}


def _validate_forwarder(body: dict):
    import re as _re
    name = (body.get("name") or "").strip()
    host = (body.get("host") or "").strip()
    protocol = (body.get("protocol") or "udp").lower()
    filter_pattern = (body.get("filter_pattern") or "").strip()
    min_severity = (body.get("min_severity") or "").lower()
    origin_mode = (body.get("origin_mode") or "off").lower()
    tcp_framing = (body.get("tcp_framing") or "newline").lower()
    try:
        port = int(body.get("port", 0))
    except (TypeError, ValueError):
        return None, "port must be a number"
    if not name:
        return None, "name is required"
    if not host:
        return None, "host is required"
    if not (1 <= port <= 65535):
        return None, "port must be 1-65535"
    if protocol not in ("udp", "tcp"):
        return None, "protocol must be udp or tcp"
    if min_severity not in VALID_SEVERITIES:
        return None, f"min_severity must be blank or one of {sorted(VALID_SEVERITIES - {''})}"
    if origin_mode not in ("off", "hostname", "sd", "both"):
        return None, "origin_mode must be off, hostname, sd, or both"
    if tcp_framing not in ("newline", "octet"):
        return None, "tcp_framing must be newline or octet"
    if filter_pattern:
        try:
            _re.compile(filter_pattern)
        except _re.error as exc:
            return None, f"filter_pattern is not a valid regex: {exc}"
    return {
        "name": name, "host": host, "port": port, "protocol": protocol,
        "enabled": 1 if body.get("enabled", True) else 0,
        "filter_pattern": filter_pattern, "min_severity": min_severity,
        "origin_mode": origin_mode,
        "tcp_framing": tcp_framing,
    }, None


@app.route("/api/forwarders", methods=["GET"])
def api_forwarders_list():
    ensure_forwarders_table()
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM forwarders ORDER BY id").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/forwarders", methods=["POST"])
@admin_required
def api_forwarders_create():
    ensure_forwarders_table()
    cfg, err = _validate_forwarder(request.get_json(force=True, silent=True) or {})
    if err:
        return jsonify({"error": err}), 400
    conn = get_conn()
    new_id = conn.insert_returning_id(
        """INSERT INTO forwarders (name, host, port, protocol, enabled,
                                   filter_pattern, min_severity, origin_mode, tcp_framing)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (cfg["name"], cfg["host"], cfg["port"], cfg["protocol"],
         cfg["enabled"], cfg["filter_pattern"], cfg["min_severity"],
         cfg["origin_mode"], cfg["tcp_framing"]))
    conn.commit()
    conn.close()
    audit("forwarder_created", target=cfg["name"],
          detail=f"{cfg['protocol']}://{cfg['host']}:{cfg['port']}")
    return jsonify({"id": new_id, "ok": True})


@app.route("/api/forwarders/<int:fw_id>", methods=["PUT"])
@admin_required
def api_forwarders_update(fw_id):
    ensure_forwarders_table()
    body = request.get_json(force=True, silent=True) or {}
    conn = get_conn()
    existing = conn.execute("SELECT * FROM forwarders WHERE id=?", (fw_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "not found"}), 404
    merged = dict(existing)
    merged.update({k: v for k, v in body.items() if k in
                   ("name", "host", "port", "protocol", "enabled",
                    "filter_pattern", "min_severity", "origin_mode", "tcp_framing")})
    cfg, err = _validate_forwarder(merged)
    if err:
        conn.close()
        return jsonify({"error": err}), 400
    conn.execute(
        """UPDATE forwarders SET name=?, host=?, port=?, protocol=?, enabled=?,
                                 filter_pattern=?, min_severity=?, origin_mode=?,
                                 tcp_framing=? WHERE id=?""",
        (cfg["name"], cfg["host"], cfg["port"], cfg["protocol"], cfg["enabled"],
         cfg["filter_pattern"], cfg["min_severity"], cfg["origin_mode"],
         cfg["tcp_framing"], fw_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/forwarders/<int:fw_id>", methods=["DELETE"])
@admin_required
def api_forwarders_delete(fw_id):
    ensure_forwarders_table()
    conn = get_conn()
    conn.execute("DELETE FROM forwarders WHERE id=?", (fw_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/forwarders/<int:fw_id>/test", methods=["POST"])
def api_forwarders_test(fw_id):
    """Sends one test syslog message to the destination from the
    dashboard process. Note: a UDP 'success' only means the packet was
    handed to the network stack — confirm receipt on the far end."""
    import socket as _socket
    from datetime import datetime as _dt, timezone as _tz
    ensure_forwarders_table()
    conn = get_conn()
    fw = conn.execute("SELECT * FROM forwarders WHERE id=?", (fw_id,)).fetchone()
    conn.close()
    if not fw:
        return jsonify({"error": "not found"}), 404

    ts = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    msg = f"<14>1 {ts} mini-siem-dashboard test - - - Test message for forwarder '{fw['name']}'"
    try:
        if fw["protocol"] == "tcp":
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((fw["host"], int(fw["port"])))
            s.sendall((msg + "\n").encode())
            s.close()
        else:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.sendto(msg.encode(), (fw["host"], int(fw["port"])))
            s.close()
        note = ("sent (TCP connection succeeded)" if fw["protocol"] == "tcp"
                else "sent (UDP is fire-and-forget — verify receipt on the destination)")
        return jsonify({"ok": True, "note": note})
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 502


# ---------------------------------------------------------------------------
# AI SOC analyst endpoints (used by /ai)
# ---------------------------------------------------------------------------

@app.route("/api/ai/config", methods=["GET"])
def api_ai_config_get():
    cfg = get_ai_config()
    # never echo the API key back to the browser; just say whether one is set
    return jsonify({
        "ai_enabled": cfg["ai_enabled"] == "true",
        "ai_mode": cfg.get("ai_mode", "local"),
        "ai_base_url": cfg["ai_base_url"],
        "ai_model": cfg["ai_model"],
        "ai_api_key_set": bool(cfg["ai_api_key"]),
        "ai_auto_triage": cfg.get("ai_auto_triage", "true") == "true",
        "ai_auto_triage_min_severity": cfg.get("ai_auto_triage_min_severity", ""),
        "ai_auto_triage_max_age_hours": int(cfg.get("ai_auto_triage_max_age_hours", "0") or 0),
        "ai_system_prompt": cfg.get("ai_system_prompt", ""),
        "ai_user_template": cfg.get("ai_user_template", ""),
        "ai_max_tokens": int(cfg.get("ai_max_tokens", "900") or 900),
        "ai_default_system_prompt": ai_soc.TRIAGE_SYSTEM,
    })


@app.route("/api/ai/config", methods=["POST"])
@admin_required
def api_ai_config_set():
    body = request.get_json(force=True, silent=True) or {}
    updates = {}
    if "ai_enabled" in body:
        updates["ai_enabled"] = "true" if body["ai_enabled"] else "false"
    if "ai_mode" in body:
        updates["ai_mode"] = "external" if body["ai_mode"] == "external" else "local"
    if "ai_base_url" in body:
        updates["ai_base_url"] = str(body["ai_base_url"]).strip()
    if "ai_model" in body:
        updates["ai_model"] = str(body["ai_model"]).strip()
    if "ai_auto_triage" in body:
        updates["ai_auto_triage"] = "true" if body["ai_auto_triage"] else "false"
    if "ai_auto_triage_min_severity" in body:
        updates["ai_auto_triage_min_severity"] = str(body["ai_auto_triage_min_severity"]).strip()
    if "ai_auto_triage_max_age_hours" in body:
        try:
            updates["ai_auto_triage_max_age_hours"] = str(max(0, min(int(body["ai_auto_triage_max_age_hours"] or 0), 8760)))
        except (TypeError, ValueError):
            pass
    if "ai_system_prompt" in body:
        updates["ai_system_prompt"] = str(body["ai_system_prompt"])[:8000]
    if "ai_user_template" in body:
        updates["ai_user_template"] = str(body["ai_user_template"])[:8000]
    if "ai_max_tokens" in body:
        try:
            updates["ai_max_tokens"] = str(max(64, min(int(body["ai_max_tokens"] or 900), 8192)))
        except (TypeError, ValueError):
            pass
    # only overwrite the key if a non-empty value is provided
    if body.get("ai_api_key"):
        updates["ai_api_key"] = str(body["ai_api_key"]).strip()
    save_ai_config(updates)
    # Record WHAT changed with values for non-sensitive settings, so the trail
    # is meaningful (e.g. "ai_enabled=false"). The API key is never recorded as
    # a value — only that it was updated.
    SENSITIVE = {"ai_api_key"}
    SUMMARIZE = {"ai_system_prompt", "ai_user_template"}  # long free text
    parts = []
    for k, v in updates.items():
        if k in SENSITIVE:
            parts.append(f"{k} (updated)")
        elif k in SUMMARIZE:
            parts.append(f"{k} ({'set' if str(v).strip() else 'cleared'})")
        else:
            parts.append(f"{k}={v}")
    audit("ai_config_changed", detail=", ".join(parts) or "no changes")
    return jsonify({"ok": True})


def _ai_enabled():
    return get_ai_config()["ai_enabled"] == "true"


@app.route("/api/ai/test", methods=["POST"])
def api_ai_test():
    if not _ai_enabled():
        return jsonify({"ok": False, "error": "AI Analyst is turned off. Enable it first."}), 400
    cfg = get_ai_config()
    if cfg.get("ai_mode") == "external" and not cfg.get("ai_api_key"):
        return jsonify({"ok": False, "error": "External mode needs an API token — none is set."}), 400
    ok, detail = _llm_from_config().test()
    return (jsonify({"ok": True, "detail": detail}) if ok
            else (jsonify({"ok": False, "error": detail}), 502))


@app.route("/api/ai/queue/stats", methods=["GET"])
def api_ai_queue_stats():
    conn = get_conn()
    def cnt(where):
        r = conn.execute(f"SELECT COUNT(*) AS c FROM alerts WHERE {where}").fetchone()
        return r["c"] if hasattr(r, "keys") else r[0]
    stats = {
        "queued": cnt("ai_status IS NULL OR ai_status = 'pending'"),
        "failed": cnt("ai_status = 'error'"),
        "done": cnt("ai_status = 'done'"),
        "skipped": cnt("ai_status = 'skipped'"),
    }
    conn.close()
    return jsonify(stats)


@app.route("/api/ai/queue/retry", methods=["POST"])
def api_ai_queue_retry():
    """Reset failed, stuck, and skipped alerts so the triage worker
    re-evaluates them — use after the LLM box comes back online. Alerts
    below the min-severity or older than the max-age simply get
    re-skipped on the next pass, so this is always safe."""
    conn = get_conn()
    cur = conn.execute(
        "UPDATE alerts SET ai_status='pending', ai_attempts=0 "
        "WHERE ai_status IS NULL OR ai_status IN ('error','pending','skipped')")
    conn.commit()
    n = cur.rowcount if hasattr(cur, "rowcount") else -1
    conn.close()
    audit("ai_queue_retry", detail=f"{n} alerts reset for re-triage")
    return jsonify({"ok": True, "reset": n})


@app.route("/api/ai/queue/clear", methods=["POST"])
def api_ai_queue_clear():
    """Mark all queued/failed alerts as skipped — the alerts themselves
    stay; they just won't be sent to the LLM."""
    conn = get_conn()
    cur = conn.execute(
        "UPDATE alerts SET ai_status='skipped' "
        "WHERE ai_status IS NULL OR ai_status IN ('pending','error')")
    conn.commit()
    n = cur.rowcount if hasattr(cur, "rowcount") else -1
    conn.close()
    audit("ai_queue_cleared", detail=f"{n} alerts marked skipped")
    return jsonify({"ok": True, "cleared": n})


@app.route("/api/ai/triage", methods=["POST"])
def api_ai_triage():
    if not _ai_enabled():
        return jsonify({"error": "AI Analyst is turned off. Enable it on the AI page."}), 400
    body = request.get_json(force=True, silent=True) or {}
    alert_id = body.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id is required"}), 400
    conn = get_conn()
    ctx = ai_soc.gather_alert_context(conn, int(alert_id))
    conn.close()
    if not ctx:
        return jsonify({"error": "alert not found"}), 404
    _cfg = get_ai_config()
    messages = ai_soc.build_triage_messages(
        ctx, system_prompt=_cfg.get("ai_system_prompt"),
        user_template=_cfg.get("ai_user_template"))
    try:
        answer = _llm_from_config().chat(
            messages, max_tokens=int(_cfg.get("ai_max_tokens", "900") or 900))
    except Exception as exc:
        return jsonify({"error": f"LLM call failed: {type(exc).__name__}: {exc}"}), 502
    return jsonify({
        "answer": answer,
        "context_summary": {
            "related_events": len(ctx["related"]),
            "source_history_events": len(ctx["src_history"]),
            "source": ctx["alert"]["source_ip"],
        },
    })


@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    if not _ai_enabled():
        return jsonify({"error": "AI Analyst is turned off. Enable it on the AI page."}), 400
    body = request.get_json(force=True, silent=True) or {}
    question = (body.get("question") or "").strip()
    history = body.get("history") or []
    if not question:
        return jsonify({"error": "question is required"}), 400
    conn = get_conn()
    ctx = ai_soc.gather_chat_context(conn, question)
    conn.close()
    _cfg = get_ai_config()
    messages = ai_soc.build_chat_messages(
        ctx, question, history, system_prompt=_cfg.get("ai_system_prompt"))
    try:
        answer = _llm_from_config().chat(
            messages, max_tokens=int(_cfg.get("ai_max_tokens", "900") or 900))
    except Exception as exc:
        return jsonify({"error": f"LLM call failed: {type(exc).__name__}: {exc}"}), 502
    return jsonify({
        "answer": answer,
        "context_summary": {
            "matched_events": len(ctx["matches"]),
            "keywords": ctx["keywords"],
        },
    })


# ---------------------------------------------------------------------------
# Health endpoints (/health page)
# ---------------------------------------------------------------------------

@app.route("/healthz")
def healthz():
    """Unauthenticated minimal liveness probe for external monitors —
    intentionally exposes no data."""
    return jsonify({"status": "ok"})


@app.route("/api/health")
def api_health():
    conn = get_conn()
    try:
        snapshot = health_mod.collect(conn, _db_config())
    finally:
        conn.close()
    return jsonify(snapshot)


@app.route("/api/db/integrity", methods=["GET"])
def api_db_integrity():
    quick = request.args.get("full", "").lower() not in ("1", "true", "yes")
    ok, detail = dbmod.integrity_check(_db_config(), quick=quick)
    info = dbmod.db_file_info(_db_config())
    return jsonify({"ok": ok, "detail": detail, "quick": quick, "file": info})


@app.route("/api/db/backup", methods=["POST"])
@admin_required
def api_db_backup():
    """Create a WAL-safe online backup of the sqlite DB into ./backups
    (or a configured dir), then integrity-check the copy."""
    import os
    import sqlite3
    from datetime import datetime, timezone
    cfg = _db_config()
    if cfg.get("backend") != "sqlite":
        return jsonify({"error": "online backup endpoint is for the SQLite backend"}), 400
    src_path = cfg["sqlite"]["path"]
    backup_dir = cfg_get("db_backup_dir", "") or os.path.join(
        os.path.dirname(os.path.abspath(src_path)) or ".", "backups")
    try:
        os.makedirs(backup_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(backup_dir, f"siem-{stamp}.db")
        # sqlite online backup API — safe while the DB is in use
        src = sqlite3.connect(src_path)
        dst = sqlite3.connect(dest)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()
        # verify the copy
        ok, detail = dbmod.integrity_check(dbmod.config_from_path(dest), quick=False)
        size = os.path.getsize(dest)
        # rotate: keep newest 14
        backups = sorted(f for f in os.listdir(backup_dir)
                         if f.startswith("siem-") and f.endswith(".db"))
        removed = 0
        for old in backups[:-14]:
            try:
                os.remove(os.path.join(backup_dir, old)); removed += 1
            except OSError:
                pass
        audit("db_backup", target=dest, detail=f"{size} bytes, integrity={'ok' if ok else detail}")
        return jsonify({"ok": True, "path": dest, "size_bytes": size,
                        "verified": ok, "verify_detail": detail,
                        "rotated_out": removed, "dir": backup_dir})
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


# ---------------------------------------------------------------------------
# User management (Setup page)
# ---------------------------------------------------------------------------

@app.route("/api/unidentified-log", methods=["GET"])
@admin_required
def api_unidentified_log_get():
    """The most recent JSON event that matched no source profile or mapped
    poorly — a sample the operator can build a mapping profile from."""
    import json as _json
    raw = cfg_get("last_unidentified_log", "")
    if not raw:
        return jsonify({"present": False})
    try:
        data = _json.loads(raw)
    except ValueError:
        return jsonify({"present": False})
    data["present"] = True
    return jsonify(data)


@app.route("/api/unidentified-log", methods=["DELETE"])
@admin_required
def api_unidentified_log_clear():
    cfg_set(last_unidentified_log="")
    audit("unidentified_log_cleared")
    return jsonify({"ok": True})


@app.route("/api/idle-timeout", methods=["GET"])
def api_idle_timeout_get():
    val = cfg_get("idle_timeout_minutes", "")
    try:
        minutes = int(float(val)) if str(val).strip() else 0
    except ValueError:
        minutes = 0
    return jsonify({"minutes": minutes})


@app.route("/api/idle-timeout", methods=["POST"])
@admin_required
def api_idle_timeout_set():
    body = request.get_json(silent=True) or {}
    raw = body.get("minutes", "")
    if raw in ("", None):
        minutes = 0  # blank / 0 disables the timeout
    else:
        try:
            minutes = int(float(raw))
        except (ValueError, TypeError):
            return jsonify({"error": "minutes must be a whole number (0 disables)"}), 400
    if minutes < 0:
        return jsonify({"error": "minutes cannot be negative"}), 400
    if minutes > 100000:
        return jsonify({"error": "that timeout is unreasonably large"}), 400
    cfg_set(idle_timeout_minutes=str(minutes))
    audit("idle_timeout_changed", detail=f"{minutes} min" if minutes else "disabled")
    return jsonify({"ok": True, "minutes": minutes})


@app.route("/api/users", methods=["GET"])
def api_users_list():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT username, role, auth_source, must_change_password, created_at FROM users ORDER BY username").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/users", methods=["POST"])
@admin_required
def api_users_create():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = (body.get("role") or "admin").strip()
    if not username:
        return jsonify({"error": "username is required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    conn = get_conn()
    if auth.get_user(conn, username):
        conn.close()
        return jsonify({"error": "user already exists"}), 409
    from werkzeug.security import generate_password_hash
    from datetime import datetime, timezone
    conn.execute(
        """INSERT INTO users (username, password_hash, role, auth_source,
                              must_change_password, created_at)
           VALUES (?,?,?,?,?,?)""",
        (username, generate_password_hash(password), role, "local", 0,
         datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    audit("user_created", target=username, detail=f"role: {role}")
    return jsonify({"ok": True})


@app.route("/api/users/<username>", methods=["DELETE"])
@admin_required
def api_users_delete(username):
    if username == auth.current_user():
        return jsonify({"error": "you cannot delete the account you're logged in as"}), 400
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    total = n["c"] if isinstance(n, dict) else n[0]
    if total <= 1:
        conn.close()
        return jsonify({"error": "cannot delete the last remaining user"}), 400
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    audit("user_deleted", target=username)
    return jsonify({"ok": True})


@app.route("/api/users/password", methods=["POST"])
def api_users_password():
    if not auth.current_user():
        return jsonify({"error": "not authenticated"}), 401
    body = request.get_json(force=True, silent=True) or {}
    current = body.get("current_password") or ""
    new = body.get("new_password") or ""
    conn = get_conn()
    user = auth.verify_local(conn, auth.current_user(), current)
    if not user:
        conn.close()
        return jsonify({"error": "current password is incorrect"}), 400
    if len(new) < 8:
        conn.close()
        return jsonify({"error": "new password must be at least 8 characters"}), 400
    if new == auth.DEFAULT_ADMIN_PASS:
        conn.close()
        return jsonify({"error": "choose a password other than the default"}), 400
    auth.set_password(conn, auth.current_user(), new)
    conn.close()
    session["must_change"] = False
    audit("password_changed", detail="via Setup page")
    return jsonify({"ok": True})


@app.route("/api/auth/methods", methods=["GET"])
def api_auth_methods():
    """Report which login methods are enabled (read-only view of
    auth-config.json) for display on the Setup page."""
    ac = AUTH_CONFIG or auth.load_auth_config()
    return jsonify({
        "local": ac.get("local_auth", {}).get("enabled", True),
        "oauth": {
            "enabled": bool(ac.get("oauth", {}).get("enabled")),
            "provider_name": ac.get("oauth", {}).get("provider_name", "SSO"),
            "configured": bool(ac.get("oauth", {}).get("client_id")),
        },
        "saml": {
            "enabled": bool(ac.get("saml", {}).get("enabled")),
            "configured": bool(ac.get("saml", {}).get("idp_sso_url")),
        },
        "note": "Edit auth-config.json and restart to change SSO settings.",
    })


# ---------------------------------------------------------------------------
# Threat intelligence (IOC) endpoints
# ---------------------------------------------------------------------------

@app.route("/api/iocs", methods=["GET"])
def api_iocs_list():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        """SELECT id, ioc_type, value, threat, source, severity, enabled, created_at
           FROM iocs ORDER BY id DESC LIMIT 2000""").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/iocs", methods=["POST"])
def api_iocs_create():
    import threatintel as ti
    body = request.get_json(force=True, silent=True) or {}
    value = (body.get("value") or "").strip()
    if not value:
        return jsonify({"error": "value is required"}), 400
    ioc_type = (body.get("ioc_type") or "").strip().lower() or ti.guess_type(value)
    if ioc_type not in ti.IOC_TYPES:
        return jsonify({"error": "ioc_type must be one of: " + ", ".join(sorted(ti.IOC_TYPES))}), 400
    sev = severity_mod.normalize((body.get("severity") or "critical")) or "critical"
    value_norm = ti.normalize_ioc(ioc_type, value)
    from datetime import datetime, timezone
    conn = get_conn()
    dup = conn.execute("SELECT id FROM iocs WHERE ioc_type=? AND value_norm=?",
                       (ioc_type, value_norm)).fetchone()
    if dup:
        conn.close()
        return jsonify({"error": "this indicator already exists"}), 409
    new_id = conn.insert_returning_id(
        """INSERT INTO iocs (ioc_type, value, value_norm, threat, source, severity, enabled, created_at)
           VALUES (?,?,?,?,?,?,1,?)""",
        (ioc_type, value, value_norm, (body.get("threat") or "").strip(),
         (body.get("source") or "manual").strip(), sev,
         datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    audit("ioc_added", target=f"{ioc_type}: {value}", detail=body.get("threat") or "")
    return jsonify({"id": new_id, "ok": True})


@app.route("/api/iocs/import", methods=["POST"])
def api_iocs_import():
    """Bulk import from pasted feed text: one indicator per line, # for
    comments, optional CSV form value,type,threat per line."""
    import threatintel as ti
    body = request.get_json(force=True, silent=True) or {}
    text = body.get("text") or ""
    if not text.strip():
        return jsonify({"error": "no feed text provided"}), 400
    sev = severity_mod.normalize((body.get("severity") or "warning")) or "warning"
    parsed = ti.parse_feed_text(
        text,
        default_type=(body.get("default_type") or "").strip().lower(),
        default_threat=(body.get("threat") or "").strip(),
        source=(body.get("source") or "pasted feed").strip(),
        severity=sev)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    added, skipped = 0, 0
    for item in parsed:
        dup = conn.execute("SELECT id FROM iocs WHERE ioc_type=? AND value_norm=?",
                           (item["ioc_type"], item["value_norm"])).fetchone()
        if dup:
            skipped += 1
            continue
        conn.execute(
            """INSERT INTO iocs (ioc_type, value, value_norm, threat, source, severity, enabled, created_at)
               VALUES (?,?,?,?,?,?,1,?)""",
            (item["ioc_type"], item["value"], item["value_norm"], item["threat"],
             item["source"], item["severity"], now))
        added += 1
    conn.commit()
    conn.close()
    audit("ioc_feed_imported", target=(body.get("source") or "pasted feed").strip(),
          detail=f"{added} added, {skipped} duplicates")
    return jsonify({"ok": True, "added": added, "skipped_duplicates": skipped})


@app.route("/api/iocs/<int:ioc_id>", methods=["PUT"])
def api_iocs_update(ioc_id):
    body = request.get_json(force=True, silent=True) or {}
    conn = get_conn()
    if "enabled" in body:
        conn.execute("UPDATE iocs SET enabled=? WHERE id=?",
                     (1 if body["enabled"] else 0, ioc_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/iocs/<int:ioc_id>", methods=["DELETE"])
@admin_required
def api_iocs_delete(ioc_id):
    conn = get_conn()
    row = conn.execute("SELECT ioc_type, value FROM iocs WHERE id=?", (ioc_id,)).fetchone()
    conn.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))
    conn.commit()
    conn.close()
    if row:
        audit("ioc_deleted", target=f"{row['ioc_type']}: {row['value']}")
    return jsonify({"ok": True})


@app.route("/api/iocs/clear", methods=["POST"])
@admin_required
def api_iocs_clear():
    """Delete IOCs by source (or all) — for replacing a whole feed."""
    body = request.get_json(force=True, silent=True) or {}
    source = (body.get("source") or "").strip()
    conn = get_conn()
    if source:
        conn.execute("DELETE FROM iocs WHERE source=?", (source,))
    else:
        conn.execute("DELETE FROM iocs")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/ioc-matches", methods=["GET"])
def api_ioc_matches():
    limit = min(int(request.args.get("limit", 100)), 1000)
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        """SELECT id, matched_at, ioc_id, ioc_type, ioc_value, threat,
                  log_id, source_ip, hostname, message
           FROM ioc_matches ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/iocs/stats", methods=["GET"])
def api_iocs_stats():
    conn = get_conn()
    def one(sql):
        r = conn.execute(sql).fetchone()
        return r["c"] if isinstance(r, dict) or hasattr(r, "keys") else r[0]
    total = one("SELECT COUNT(*) AS c FROM iocs")
    enabled = one("SELECT COUNT(*) AS c FROM iocs WHERE enabled=1")
    matches = one("SELECT COUNT(*) AS c FROM ioc_matches")
    by_type = {r["ioc_type"]: r["c"] for r in conn.execute(
        "SELECT ioc_type, COUNT(*) AS c FROM iocs GROUP BY ioc_type").fetchall()}
    conn.close()
    return jsonify({"total": total, "enabled": enabled, "total_matches": matches,
                    "by_type": by_type})


# ---------------------------------------------------------------------------
# Generic app_config accessors (reports schedule, ticket config, norm patterns)
# ---------------------------------------------------------------------------

def cfg_get(key, default=""):
    ensure_app_config()
    conn = get_conn()
    row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row and row["value"] is not None else default


def cfg_set(**kv):
    ensure_app_config()
    conn = get_conn()
    for k, v in kv.items():
        conn.execute("INSERT INTO app_config(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Search / correlation field aliases — one editable definition of "what does
# 'source', 'host', and 'destination' mean" used by BOTH Log Search and the
# correlation playbook engine, so the two never disagree about identity.
#
# The base columns (source_ip / hostname / destination) are always checked
# first — they're already correct for most sources (e.g. Fortigate's src=
# already overwrites source_ip, profiles already map host correctly). The
# aliases below are ADDITIONAL raw field names (as they land in log_fields)
# to also treat as meaning the same concept — the safety net for sources
# where the concept lives under a different name (e.g. Sophos's endpoint_ip
# is a source; Sophos's location is already handled by the host profile
# mapping, listed here too as a fallback for un-profiled/future sources).
#
# This resolves entirely at QUERY TIME (not ingest time), so editing it
# takes effect immediately on ALL existing data — no reindex, ever.
_DEFAULT_SEARCH_ALIASES = {
    "source": ["endpoint_ip", "src", "srcip", "src_ip"],
    "host": ["computer", "machinename", "endpoint_name", "device", "location"],
    "destination": ["dst", "dest", "target", "dhost", "destination_ip"],
}


def get_search_aliases():
    """Returns {'source': [...], 'host': [...], 'destination': [...]}."""
    raw = cfg_get("search_aliases", "")
    if not raw:
        return {k: list(v) for k, v in _DEFAULT_SEARCH_ALIASES.items()}
    try:
        import json as _json
        d = _json.loads(raw)
        out = {}
        for concept in ("source", "host", "destination"):
            v = d.get(concept)
            out[concept] = v if isinstance(v, list) else list(_DEFAULT_SEARCH_ALIASES[concept])
        return out
    except Exception:
        return {k: list(v) for k, v in _DEFAULT_SEARCH_ALIASES.items()}


def set_search_aliases(d):
    import json as _json
    clean = {}
    for concept in ("source", "host", "destination"):
        vals = d.get(concept) or []
        if isinstance(vals, str):
            vals = [v.strip() for v in vals.split(",") if v.strip()]
        clean[concept] = [str(v).strip().lower() for v in vals if str(v).strip()][:20]
    cfg_set(search_aliases=_json.dumps(clean))
    return clean


@app.route("/api/search-aliases", methods=["GET"])
def api_search_aliases_get():
    return jsonify(get_search_aliases())


@app.route("/api/search-aliases", methods=["POST"])
@admin_required
def api_search_aliases_set():
    body = request.get_json(force=True, silent=True) or {}
    saved = set_search_aliases(body)
    audit("search_aliases_updated", detail=str(saved))
    return jsonify(saved)


# ---------------------------------------------------------------------------
# API poller connectors (OAuth2 client-credentials log pullers)
# ---------------------------------------------------------------------------
import secretbox as _secretbox
import api_poller as _api_poller

_POLLER_MANAGER = None


def _secretbox_master():
    """Fetch (or lazily create) the master key used to encrypt connector
    secrets. Stored once in app_config."""
    m = cfg_get("secretbox_master", "")
    if not m:
        m = _secretbox.generate_master()
        cfg_set(secretbox_master=m)
    return m


def _resolve_poller_secret(row):
    """Return the plaintext client_secret for a poller row, honoring its
    storage mode. 'encrypted' -> decrypt via secretbox. 'vaultgate' ->
    not yet wired; raises so the poller records a clear error."""
    mode = (row.get("secret_mode") or "encrypted").lower()
    if mode == "vaultgate":
        raise RuntimeError("VaultGate secret storage is not configured yet")
    enc = row.get("client_secret") or ""
    if not enc:
        return ""
    return _secretbox.decrypt(enc, _secretbox_master())


def start_poller_manager():
    """Start the background poller manager (called once at startup)."""
    global _POLLER_MANAGER
    if _POLLER_MANAGER is not None:
        return

    def ingest_event(event):
        # route through the same pipeline as syslog/API ingest by emitting a
        # JSON line the listener's parser will recognize as a JSON event. The
        # SOURCE column shows the connector name (e.g. 'sophos-central'); the
        # endpoint IP is folded into the JSON so it becomes a searchable field.
        import json as _json
        connector = event.get("_connector") or "api-poller"
        payload = event.get("_json", event)
        if isinstance(payload, dict) and event.get("_endpoint_ip"):
            payload = dict(payload)
            payload.setdefault("endpoint_ip", event["_endpoint_ip"])
        _ingest_raw(_json.dumps(payload, ensure_ascii=False), connector)

    _POLLER_MANAGER = _api_poller.PollerManager(
        conn_factory=get_conn,
        ingest_fn=ingest_event,
        resolve_secret_fn=_resolve_poller_secret)
    _POLLER_MANAGER.start()


def _poller_public(row):
    """Row as safe JSON — never expose the stored secret."""
    d = dict(row)
    d.pop("client_secret", None)
    d["has_secret"] = bool(row.get("client_secret"))
    return d


@app.route("/api/pollers", methods=["GET"])
@admin_required
def api_pollers_list():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM api_pollers ORDER BY id").fetchall()]
    conn.close()
    return jsonify([_poller_public(r) for r in rows])


# ---------------------------------------------------------------------------
# Source profiles (data-driven JSON field mapping)
# ---------------------------------------------------------------------------
_PROFILE_MATCH_TYPES = ("source_ip", "key_present", "app_contains")
_PROFILE_FIELDS = ("name", "match_type", "match_value", "map_host", "map_message",
                   "map_app", "map_msgid", "map_severity", "map_timestamp",
                   "ts_format", "priority", "enabled")


def _validate_profile(body, creating):
    name = (body.get("name") or "").strip()
    match_type = (body.get("match_type") or "source_ip").lower()
    if creating and not name:
        return None, "name is required"
    if match_type not in _PROFILE_MATCH_TYPES:
        return None, f"match_type must be one of {list(_PROFILE_MATCH_TYPES)}"
    try:
        priority = int(body.get("priority", 100))
    except (ValueError, TypeError):
        return None, "priority must be a number"
    cfg = {
        "name": name,
        "match_type": match_type,
        "match_value": (body.get("match_value") or "").strip(),
        "map_host": (body.get("map_host") or "").strip(),
        "map_message": (body.get("map_message") or "").strip(),
        "map_app": (body.get("map_app") or "").strip(),
        "map_msgid": (body.get("map_msgid") or "").strip(),
        "map_severity": (body.get("map_severity") or "").strip(),
        "map_timestamp": (body.get("map_timestamp") or "").strip(),
        "ts_format": (body.get("ts_format") or "").strip(),
        "priority": priority,
        "enabled": 1 if body.get("enabled", True) else 0,
    }
    return cfg, None


@app.route("/api/profiles", methods=["GET"])
@admin_required
def api_profiles_list():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM source_profiles ORDER BY priority ASC, id ASC").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/profiles", methods=["POST"])
@admin_required
def api_profiles_create():
    body = request.get_json(silent=True) or {}
    cfg, err = _validate_profile(body, creating=True)
    if err:
        return jsonify({"error": err}), 400
    conn = get_conn()
    conn.execute(
        """INSERT INTO source_profiles
           (name, match_type, match_value, map_host, map_message, map_app,
            map_msgid, map_severity, map_timestamp, ts_format, priority, enabled)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cfg["name"], cfg["match_type"], cfg["match_value"], cfg["map_host"],
         cfg["map_message"], cfg["map_app"], cfg["map_msgid"], cfg["map_severity"],
         cfg["map_timestamp"], cfg["ts_format"], cfg["priority"], cfg["enabled"]))
    conn.commit(); conn.close()
    audit("profile_created", target=cfg["name"])
    return jsonify({"ok": True})


@app.route("/api/profiles/<int:pid>", methods=["PUT"])
@admin_required
def api_profiles_update(pid):
    body = request.get_json(silent=True) or {}
    conn = get_conn()
    existing = conn.execute("SELECT * FROM source_profiles WHERE id=?", (pid,)).fetchone()
    if not existing:
        conn.close(); return jsonify({"error": "not found"}), 404
    merged = dict(existing)
    merged.update({k: v for k, v in body.items() if k in _PROFILE_FIELDS})
    cfg, err = _validate_profile(merged, creating=False)
    if err:
        conn.close(); return jsonify({"error": err}), 400
    conn.execute(
        """UPDATE source_profiles SET name=?, match_type=?, match_value=?,
               map_host=?, map_message=?, map_app=?, map_msgid=?, map_severity=?,
               map_timestamp=?, ts_format=?, priority=?, enabled=? WHERE id=?""",
        (cfg["name"], cfg["match_type"], cfg["match_value"], cfg["map_host"],
         cfg["map_message"], cfg["map_app"], cfg["map_msgid"], cfg["map_severity"],
         cfg["map_timestamp"], cfg["ts_format"], cfg["priority"], cfg["enabled"], pid))
    conn.commit(); conn.close()
    audit("profile_updated", target=cfg["name"])
    return jsonify({"ok": True})


@app.route("/api/profiles/<int:pid>", methods=["DELETE"])
@admin_required
def api_profiles_delete(pid):
    conn = get_conn()
    row = conn.execute("SELECT name FROM source_profiles WHERE id=?", (pid,)).fetchone()
    conn.execute("DELETE FROM source_profiles WHERE id=?", (pid,))
    conn.commit(); conn.close()
    audit("profile_deleted", target=(row["name"] if row else str(pid)))
    return jsonify({"ok": True})


@app.route("/api/profiles/preview", methods=["POST"])
@admin_required
def api_profiles_preview():
    """Given a raw JSON event and a profile definition (or a saved profile id),
    show how the profile would map it — the tester behind the UI. Does not
    store anything."""
    import json as _json
    import profiles as _profiles_mod
    body = request.get_json(silent=True) or {}
    raw = body.get("raw", "")
    # parse the raw event (accept a JSON object or a JSON string)
    obj = None
    if isinstance(raw, dict):
        obj = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            obj = _json.loads(raw)
        except ValueError:
            return jsonify({"error": "raw is not valid JSON"}), 400
    if not isinstance(obj, dict):
        return jsonify({"error": "raw must be a JSON object"}), 400

    # profile source: an inline profile body, or a saved id
    profile = None
    if body.get("profile_id"):
        conn = get_conn()
        r = conn.execute("SELECT * FROM source_profiles WHERE id=?",
                         (body["profile_id"],)).fetchone()
        conn.close()
        if not r:
            return jsonify({"error": "profile_id not found"}), 404
        profile = dict(r)
    elif body.get("profile"):
        cfg, err = _validate_profile(body["profile"], creating=False)
        if err:
            return jsonify({"error": err}), 400
        profile = cfg
    else:
        return jsonify({"error": "supply a profile or profile_id"}), 400

    mapped = _profiles_mod.apply_profile(profile, obj)
    # also report which key won each mapping, for the UI
    return jsonify({
        "mapped": mapped,
        "keys": sorted(list(obj.keys())),
        "matches": _profile_matches(profile, obj, body.get("source", "")),
    })


def _profile_matches(profile, obj, source_ip):
    """Would this profile match the given event? (mirrors profiles.match_profile
    for a single profile.)"""
    mt = profile.get("match_type") or "source_ip"
    mv = (profile.get("match_value") or "").strip()
    if mt == "source_ip":
        return source_ip == mv
    if mt == "key_present":
        return bool(mv) and mv in obj
    if mt == "app_contains":
        app = str(obj.get("app") or obj.get("app_name") or "")
        return bool(mv) and mv.lower() in app.lower()
    return False


_POLLER_SCHEMES = ("oauth2_client_credentials", "oauth2_sophos", "api_key")


def _validate_poller(body, creating):
    name = (body.get("name") or "").strip()
    scheme = (body.get("auth_scheme") or "oauth2_client_credentials").lower()
    token_url = (body.get("token_url") or "").strip()
    events_url = (body.get("events_url") or "").strip()
    whoami_url = (body.get("whoami_url") or "").strip()
    tenant_header = (body.get("tenant_header") or "").strip()
    api_key_header = (body.get("api_key_header") or "").strip()
    client_id = (body.get("client_id") or "").strip()
    secret_mode = (body.get("secret_mode") or "encrypted").lower()

    if scheme not in _POLLER_SCHEMES:
        return None, f"auth_scheme must be one of {list(_POLLER_SCHEMES)}"
    if secret_mode not in ("encrypted", "vaultgate"):
        return None, "secret_mode must be encrypted or vaultgate"
    if creating and (not name or not events_url):
        return None, "name and events_url are required"

    # per-scheme required fields
    if scheme in ("oauth2_client_credentials", "oauth2_sophos"):
        if creating and (not token_url or not client_id):
            return None, "OAuth2 schemes require a token URL and client ID"
        for u in (token_url, whoami_url):
            if u and not (u.startswith("http://") or u.startswith("https://")):
                return None, "Token and Whoami URLs must start with http:// or https://"
    if scheme == "oauth2_sophos" and creating and not whoami_url:
        return None, "The Sophos scheme requires a Whoami URL"
    # api_key scheme: secret is the key; header name optional (defaults X-API-Key)

    # events_url: absolute, OR a path when the sophos scheme resolves the host
    # (leading slash optional — the poller normalizes it).
    is_abs = events_url.startswith("http://") or events_url.startswith("https://")
    if events_url and not is_abs:
        if not (scheme == "oauth2_sophos" and whoami_url):
            return None, ("Events URL must be a full http(s) URL — a path is only "
                          "allowed with the Sophos scheme (host comes from whoami)")
    try:
        interval = int(body.get("interval_seconds", 60))
        lookback = int(body.get("initial_lookback_seconds", 86400))
    except (ValueError, TypeError):
        return None, "interval_seconds and initial_lookback_seconds must be numbers"
    if interval < 15:
        return None, "interval_seconds must be at least 15"
    return {
        "name": name, "auth_scheme": scheme,
        "token_url": token_url, "events_url": events_url, "whoami_url": whoami_url,
        "tenant_header": tenant_header, "api_key_header": api_key_header,
        "client_id": client_id, "secret_mode": secret_mode,
        "scope": (body.get("scope") or "").strip(),
        "interval_seconds": interval,
        "initial_lookback_seconds": lookback,
        "enabled": 1 if body.get("enabled") else 0,
    }, None


@app.route("/api/pollers", methods=["POST"])
@admin_required
def api_pollers_create():
    body = request.get_json(silent=True) or {}
    cfg, err = _validate_poller(body, creating=True)
    if err:
        return jsonify({"error": err}), 400
    # encrypt the secret if provided and mode is encrypted
    secret_plain = body.get("client_secret") or ""
    enc = ""
    if cfg["secret_mode"] == "encrypted" and secret_plain:
        enc = _secretbox.encrypt(secret_plain, _secretbox_master())
    conn = get_conn()
    conn.execute(
        """INSERT INTO api_pollers
           (name, auth_scheme, token_url, events_url, whoami_url, tenant_header,
            api_key_header, client_id, client_secret, secret_mode, scope,
            interval_seconds, initial_lookback_seconds, enabled)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cfg["name"], cfg["auth_scheme"], cfg["token_url"], cfg["events_url"],
         cfg["whoami_url"], cfg["tenant_header"], cfg["api_key_header"],
         cfg["client_id"], enc, cfg["secret_mode"], cfg["scope"],
         cfg["interval_seconds"], cfg["initial_lookback_seconds"], cfg["enabled"]))
    conn.commit(); conn.close()
    audit("poller_created", target=cfg["name"], detail=f"mode={cfg['secret_mode']}")
    return jsonify({"ok": True})


@app.route("/api/pollers/<int:pid>", methods=["PUT"])
@admin_required
def api_pollers_update(pid):
    body = request.get_json(silent=True) or {}
    conn = get_conn()
    existing = conn.execute("SELECT * FROM api_pollers WHERE id=?", (pid,)).fetchone()
    if not existing:
        conn.close(); return jsonify({"error": "not found"}), 404
    merged = dict(existing)
    merged.update({k: v for k, v in body.items()
                   if k in ("name", "auth_scheme", "token_url", "events_url",
                            "whoami_url", "tenant_header", "api_key_header",
                            "client_id", "secret_mode", "scope", "interval_seconds",
                            "initial_lookback_seconds", "enabled")})
    cfg, err = _validate_poller(merged, creating=False)
    if err:
        conn.close(); return jsonify({"error": err}), 400
    # only re-encrypt the secret if a new one was explicitly supplied
    if "client_secret" in body and body.get("client_secret"):
        enc = (_secretbox.encrypt(body["client_secret"], _secretbox_master())
               if cfg["secret_mode"] == "encrypted" else "")
        conn.execute("UPDATE api_pollers SET client_secret=? WHERE id=?", (enc, pid))
    conn.execute(
        """UPDATE api_pollers SET name=?, auth_scheme=?, token_url=?, events_url=?,
               whoami_url=?, tenant_header=?, api_key_header=?, client_id=?,
               secret_mode=?, scope=?, interval_seconds=?,
               initial_lookback_seconds=?, enabled=? WHERE id=?""",
        (cfg["name"], cfg["auth_scheme"], cfg["token_url"], cfg["events_url"],
         cfg["whoami_url"], cfg["tenant_header"], cfg["api_key_header"],
         cfg["client_id"], cfg["secret_mode"], cfg["scope"], cfg["interval_seconds"],
         cfg["initial_lookback_seconds"], cfg["enabled"], pid))
    conn.commit(); conn.close()
    audit("poller_updated", target=cfg["name"])
    return jsonify({"ok": True})


@app.route("/api/pollers/<int:pid>", methods=["DELETE"])
@admin_required
def api_pollers_delete(pid):
    conn = get_conn()
    row = conn.execute("SELECT name FROM api_pollers WHERE id=?", (pid,)).fetchone()
    conn.execute("DELETE FROM api_pollers WHERE id=?", (pid,))
    conn.commit(); conn.close()
    audit("poller_deleted", target=(row["name"] if row else str(pid)))
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Playbook reports
# ---------------------------------------------------------------------------

@app.route("/api/reports/run", methods=["POST"])
def api_reports_run():
    import workers
    body = request.get_json(force=True, silent=True) or {}
    days = max(1, min(int(body.get("window_days", 7)), 365))
    conn = get_conn()
    try:
        report = workers.run_playbook_report(conn, window_days=days, trigger="manual")
    finally:
        conn.close()
    audit("report_run", target=f"{days}-day window", detail=report.get("summary", ""))
    return jsonify(report)


@app.route("/api/reports", methods=["GET"])
def api_reports_list():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        """SELECT id, created_at, trigger, window_days, summary, findings
           FROM reports ORDER BY id DESC LIMIT 100""").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/reports/<int:rid>", methods=["GET"])
def api_reports_get(rid):
    import json as _json
    conn = get_conn()
    row = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "report not found"}), 404
    d = dict(row)
    d["results"] = _json.loads(d.pop("results_json") or "[]")
    return jsonify(d)


@app.route("/api/reports/<int:rid>", methods=["DELETE"])
@admin_required
def api_reports_delete(rid):
    conn = get_conn()
    conn.execute("DELETE FROM reports WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/reports/schedule", methods=["GET"])
def api_reports_schedule_get():
    return jsonify({"schedule": cfg_get("report_schedule", "off")})


@app.route("/api/reports/schedule", methods=["POST"])
def api_reports_schedule_set():
    body = request.get_json(force=True, silent=True) or {}
    sched = (body.get("schedule") or "off").lower()
    if sched not in ("off", "weekly", "monthly"):
        return jsonify({"error": "schedule must be off, weekly, or monthly"}), 400
    cfg_set(report_schedule=sched)
    audit("report_schedule_changed", target=sched)
    return jsonify({"ok": True, "schedule": sched})


# ---------------------------------------------------------------------------
# Ticket system connector
# ---------------------------------------------------------------------------

TICKET_DEFAULTS = {
    "ticket_enabled": "false",
    "ticket_url": "",
    "ticket_method": "POST",
    "ticket_headers": "{}",
    "ticket_template": "",
    "ticket_min_severity": "warning",
}


def get_ticket_settings():
    import workers, json as _json
    try:
        headers = _json.loads(cfg_get("ticket_headers", "{}") or "{}")
    except Exception:
        headers = {}
    return {
        "enabled": cfg_get("ticket_enabled", "false") == "true",
        "url": cfg_get("ticket_url", ""),
        "method": cfg_get("ticket_method", "POST") or "POST",
        "headers": headers,
        "template": cfg_get("ticket_template", "") or workers.DEFAULT_TICKET_TEMPLATE,
        "min_severity": cfg_get("ticket_min_severity", "warning"),
    }


@app.route("/api/tickets/config", methods=["GET"])
def api_tickets_config_get():
    import workers
    s = get_ticket_settings()
    # never echo credential headers back; just report which header names are set
    return jsonify({
        "enabled": s["enabled"], "url": s["url"], "method": s["method"],
        "header_names": sorted(s["headers"].keys()),
        "template": s["template"], "min_severity": s["min_severity"],
        "default_template": workers.DEFAULT_TICKET_TEMPLATE,
    })


@app.route("/api/tickets/config", methods=["POST"])
@admin_required
def api_tickets_config_set():
    import json as _json
    body = request.get_json(force=True, silent=True) or {}
    updates = {}
    if "enabled" in body:
        updates["ticket_enabled"] = "true" if body["enabled"] else "false"
    if "url" in body:
        updates["ticket_url"] = str(body["url"]).strip()
    if "method" in body:
        updates["ticket_method"] = "PUT" if str(body["method"]).upper() == "PUT" else "POST"
    if "headers" in body:
        try:
            hdrs = body["headers"] if isinstance(body["headers"], dict) else _json.loads(body["headers"] or "{}")
        except Exception:
            return jsonify({"error": "headers must be valid JSON (e.g. {\"Authorization\": \"Bearer ...\"})"}), 400
        updates["ticket_headers"] = _json.dumps(hdrs)
    if "template" in body:
        tpl = str(body["template"]).strip()
        if tpl:
            try:
                _json.loads(tpl.replace("{{", "").replace("}}", ""))
            except Exception:
                pass  # template with placeholders may not be strict JSON until rendered
        updates["ticket_template"] = tpl
    if "min_severity" in body:
        sev = severity_mod.normalize(str(body["min_severity"])) or "warning"
        updates["ticket_min_severity"] = sev
    cfg_set(**updates)
    audit("ticket_config_changed",
          detail=", ".join("headers (updated)" if k == "ticket_headers" else k for k in updates))
    return jsonify({"ok": True})


@app.route("/api/tickets/test", methods=["POST"])
def api_tickets_test():
    import workers
    w = workers.TicketWorker(get_conn, get_ticket_settings)
    ok, detail = w.send_test()
    return (jsonify({"ok": True, "detail": detail}) if ok
            else (jsonify({"ok": False, "error": detail}), 502))


# ---------------------------------------------------------------------------
# IOC feeds (external URL import)
# ---------------------------------------------------------------------------

@app.route("/api/ioc-feeds", methods=["GET"])
def api_ioc_feeds_list():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM ioc_feeds ORDER BY id DESC").fetchall()]
    conn.close()
    for r in rows:
        r["has_key"] = bool(r.pop("key_encrypted", ""))  # never return the ciphertext
    return jsonify(rows)


@app.route("/api/ioc-feeds", methods=["POST"])
def api_ioc_feeds_create():
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    url = (body.get("url") or "").strip()
    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    if not url.lower().startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400
    sev = severity_mod.normalize((body.get("severity") or "warning")) or "warning"
    refresh = max(0, min(int(body.get("refresh_hours", 0) or 0), 720))

    auth_scheme = (body.get("auth_scheme") or "none").lower()
    valid_schemes = {"none", "header", "authorization", "query_param", "basic"}
    if auth_scheme not in valid_schemes:
        return jsonify({"error": f"auth_scheme must be one of {sorted(valid_schemes)}"}), 400
    key_plain = (body.get("key") or "").strip()
    key_enc = _secretbox.encrypt(key_plain, _secretbox_master()) if key_plain else ""

    conn = get_conn()
    new_id = conn.insert_returning_id(
        """INSERT INTO ioc_feeds (name, url, severity, threat, default_type, refresh_hours,
           enabled, auth_scheme, header_name, header_prefix, query_param, basic_user, key_encrypted)
           VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?)""",
        (name, url, sev, (body.get("threat") or "").strip(),
         (body.get("default_type") or "").strip().lower(), refresh,
         auth_scheme, (body.get("header_name") or "").strip(),
         (body.get("header_prefix") or "").strip(), (body.get("query_param") or "").strip(),
         (body.get("basic_user") or "").strip(), key_enc))
    conn.commit()
    conn.close()
    audit("ioc_feed_added", target=name, detail=url)
    return jsonify({"id": new_id, "ok": True})


def _resolve_feed_key(feed_row):
    """Decrypt an ioc_feed's stored API key/token for use in a request."""
    enc = feed_row.get("key_encrypted") or ""
    if not enc:
        return ""
    return _secretbox.decrypt(enc, _secretbox_master())


@app.route("/api/ioc-feeds/<int:fid>/fetch", methods=["POST"])
def api_ioc_feeds_fetch(fid):
    import workers
    conn = get_conn()
    row = conn.execute("SELECT * FROM ioc_feeds WHERE id=?", (fid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "feed not found"}), 404
    result = workers.fetch_feed(conn, dict(row), resolve_key_fn=_resolve_feed_key)
    conn.close()
    return (jsonify(result) if result.get("ok") else (jsonify(result), 502))


@app.route("/api/ioc-feeds/<int:fid>", methods=["PUT"])
def api_ioc_feeds_update(fid):
    body = request.get_json(force=True, silent=True) or {}
    conn = get_conn()
    if "enabled" in body:
        conn.execute("UPDATE ioc_feeds SET enabled=? WHERE id=?",
                     (1 if body["enabled"] else 0, fid))
    if "refresh_hours" in body:
        conn.execute("UPDATE ioc_feeds SET refresh_hours=? WHERE id=?",
                     (max(0, min(int(body["refresh_hours"] or 0), 720)), fid))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/ioc-feeds/<int:fid>", methods=["DELETE"])
@admin_required
def api_ioc_feeds_delete(fid):
    conn = get_conn()
    conn.execute("DELETE FROM ioc_feeds WHERE id=?", (fid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Message normalization patterns (log search field extraction)
# ---------------------------------------------------------------------------

@app.route("/api/norm-patterns", methods=["GET"])
def api_norm_patterns_get():
    import json as _json
    try:
        pats = _json.loads(cfg_get("norm_patterns", "[]") or "[]")
    except Exception:
        pats = []
    return jsonify({"patterns": pats})


@app.route("/api/norm-patterns", methods=["POST"])
def api_norm_patterns_set():
    import json as _json, re as _re
    body = request.get_json(force=True, silent=True) or {}
    pats = body.get("patterns") or []
    if not isinstance(pats, list):
        return jsonify({"error": "patterns must be a list of regex strings"}), 400
    pats = [str(p).strip() for p in pats if str(p).strip()][:50]
    for p in pats:
        try:
            _re.compile(p)
        except _re.error as exc:
            return jsonify({"error": f"invalid regex '{p[:60]}': {exc}"}), 400
    cfg_set(norm_patterns=_json.dumps(pats))
    return jsonify({"ok": True, "count": len(pats)})


def _load_norm_patterns():
    import json as _json
    try:
        return _json.loads(cfg_get("norm_patterns", "[]") or "[]")
    except Exception:
        return []


def extract_fields(msg: str, patterns=None) -> dict:
    import normalize
    return normalize.extract_fields(
        msg, patterns if patterns is not None else _load_norm_patterns())


_reindex_state = {"running": False, "done_logs": 0, "max_id": 0, "last_result": ""}


@app.route("/api/norm-reindex", methods=["POST"])
def api_norm_reindex():
    """Backfill log_fields for all existing logs with current patterns.
    Runs in a background thread; poll /api/norm-reindex/status."""
    import threading
    import normalize
    if _reindex_state["running"]:
        return jsonify({"error": "re-index already running"}), 409
    _reindex_state.update({"running": True, "done_logs": 0, "max_id": 0, "last_result": ""})

    def job():
        conn = get_conn()
        try:
            def prog(done, last_id, max_id):
                _reindex_state["done_logs"] = done
                _reindex_state["max_id"] = max_id
            logs, fields = normalize.reindex(conn, progress=prog)
            _reindex_state["last_result"] = f"re-indexed {logs} logs, {fields} field values"
            print(f"[fields] {_reindex_state['last_result']}")
        except Exception as exc:
            _reindex_state["last_result"] = f"failed: {type(exc).__name__}: {exc}"
        finally:
            _reindex_state["running"] = False
            conn.close()

    threading.Thread(target=job, daemon=True).start()
    audit("norm_reindex_started")
    return jsonify({"ok": True})


@app.route("/api/norm-reindex/status")
def api_norm_reindex_status():
    return jsonify(_reindex_state)


@app.route("/api/normalize", methods=["POST"])
def api_normalize():
    body = request.get_json(force=True, silent=True) or {}
    return jsonify({"fields": extract_fields(body.get("message"))})


@app.route("/api/log-fields/<int:log_id>", methods=["GET"])
def api_log_fields(log_id):
    """Return the fields already extracted and stored for a log at ingest.
    This is what the row-expand panel shows — it reflects the real stored
    fields (JSON keys for poller sources like Sophos, key=value pairs for
    syslog like Fortigate), not a re-scan of the message text. Falls back to
    live message extraction only if no stored fields exist (e.g. old rows
    ingested before field extraction ran)."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT field, value FROM log_fields WHERE log_id=? ORDER BY field",
        (log_id,)).fetchall()
    fields = {r["field"]: r["value"] for r in rows}
    if not fields:
        # fallback: re-extract from the message for rows with no stored fields
        r = conn.execute("SELECT message FROM logs WHERE id=?", (log_id,)).fetchone()
        conn.close()
        if r and r["message"]:
            return jsonify({"fields": extract_fields(r["message"]), "stored": False})
        return jsonify({"fields": {}, "stored": False})
    conn.close()
    return jsonify({"fields": fields, "stored": True})


@app.route("/api/norm-columns", methods=["GET"])
def api_norm_columns_get():
    cols = [c.strip() for c in (cfg_get("norm_columns", "") or "").split(",") if c.strip()]
    return jsonify({"columns": cols})


@app.route("/api/norm-columns", methods=["POST"])
def api_norm_columns_set():
    body = request.get_json(force=True, silent=True) or {}
    raw = body.get("columns")
    if isinstance(raw, str):
        cols = [c.strip() for c in raw.split(",") if c.strip()]
    elif isinstance(raw, list):
        cols = [str(c).strip() for c in raw if str(c).strip()]
    else:
        cols = []
    cols = cols[:8]  # keep the table sane
    for c in cols:
        if len(c) > 40 or not c.replace("_", "").replace(".", "").replace("-", "").isalnum():
            return jsonify({"error": f"invalid field name '{c[:40]}' (letters, digits, _ . - only)"}), 400
    cfg_set(norm_columns=",".join(cols))
    return jsonify({"ok": True, "columns": cols})


# --------------------------------------------------------------------------
# HTTP log ingest API — for products that can only send logs over HTTP
# --------------------------------------------------------------------------

def _hash_api_key(raw: str) -> str:
    import hashlib
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ensure_api_keys_table():
    conn = get_conn()
    try:
        conn.execute("SELECT 1 FROM api_keys LIMIT 1")
    except Exception:
        dbmod.initialize(_db_config())
    finally:
        conn.close()


def _verify_api_key(raw: str):
    """Return the api_keys row for a valid, enabled key, or None."""
    if not raw:
        return None
    h = _hash_api_key(raw)
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_hash=? AND enabled=1", (h,)).fetchone()
    if row:
        from datetime import datetime, timezone
        conn.execute("UPDATE api_keys SET last_used=?, use_count=use_count+1 WHERE id=?",
                     (datetime.now(timezone.utc).isoformat(), row["id"]))
        conn.commit()
    conn.close()
    return row


@app.route("/api/ingest/keys", methods=["GET"])
@admin_required
def api_ingest_keys_list():
    _ensure_api_keys_table()
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(
        "SELECT id,name,key_prefix,enabled,created_at,last_used,use_count FROM api_keys ORDER BY id DESC").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/ingest/keys", methods=["POST"])
@admin_required
def api_ingest_keys_create():
    _ensure_api_keys_table()
    import secrets
    from datetime import datetime, timezone
    name = (request.json or {}).get("name", "").strip() if request.is_json else request.form.get("name", "").strip()
    if not name:
        return jsonify({"error": "a name is required (e.g. the product this key is for)"}), 400
    raw = "msk_" + secrets.token_urlsafe(32)
    conn = get_conn()
    conn.execute(
        "INSERT INTO api_keys (name, key_hash, key_prefix, enabled, created_at) VALUES (?,?,?,1,?)",
        (name, _hash_api_key(raw), raw[:12], datetime.now(timezone.utc).isoformat()))
    conn.commit(); conn.close()
    audit("api_key_created", target=name)
    # the plaintext key is returned ONCE and never stored/shown again
    return jsonify({"ok": True, "name": name, "api_key": raw,
                    "note": "Copy this now — it will not be shown again."})


@app.route("/api/ingest/keys/<int:kid>", methods=["DELETE"])
@admin_required
def api_ingest_keys_delete(kid):
    conn = get_conn()
    row = conn.execute("SELECT name FROM api_keys WHERE id=?", (kid,)).fetchone()
    conn.execute("DELETE FROM api_keys WHERE id=?", (kid,))
    conn.commit(); conn.close()
    audit("api_key_deleted", target=(row["name"] if row else str(kid)))
    return jsonify({"ok": True})


@app.route("/api/ingest/keys/<int:kid>/toggle", methods=["POST"])
@admin_required
def api_ingest_keys_toggle(kid):
    conn = get_conn()
    conn.execute("UPDATE api_keys SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (kid,))
    conn.commit()
    row = conn.execute("SELECT name,enabled FROM api_keys WHERE id=?", (kid,)).fetchone()
    conn.close()
    audit("api_key_toggled", target=(row["name"] if row else str(kid)),
          detail=f"enabled={bool(row['enabled']) if row else '?'}")
    return jsonify({"ok": True, "enabled": bool(row["enabled"]) if row else False})


def _listen_ports_configured():
    """Configured syslog listen ports, read from db-config.json (falls back
    to 514). This is the CONFIGURED value; the actually-bound ports live in
    the separate listener process. Used to label the dashboard header."""
    import os, json as _json
    path = _config_file_path()
    if os.path.exists(path):
        try:
            with open(path) as f:
                return _json.load(f).get("listen_ports") or [514]
        except (ValueError, OSError):
            pass
    return [514]


def _config_file_path():
    """The db-config.json the listener reads at startup. listen_ports live
    here (not app_config) because the listener process reads this file, not
    the database, when it binds its sockets."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "db-config.json")


@app.route("/api/listen-ports", methods=["GET"])
@admin_required
def api_listen_ports_get():
    import os, json as _json
    path = _config_file_path()
    ports = [514]
    if os.path.exists(path):
        try:
            with open(path) as f:
                ports = _json.load(f).get("listen_ports") or [514]
        except (ValueError, OSError):
            pass
    target = path if os.path.exists(path) else os.path.dirname(path)
    return jsonify({"ports": ports, "config_writable": os.access(target, os.W_OK)})


@app.route("/api/listen-ports", methods=["POST"])
@admin_required
def api_listen_ports_set():
    import os, json as _json
    body = request.get_json(silent=True) or {}
    raw = body.get("ports", "")
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(",") if p.strip()]
    elif isinstance(raw, list):
        parts = [str(p).strip() for p in raw if str(p).strip()]
    else:
        return jsonify({"error": "ports must be a list or comma-separated string"}), 400
    ports = []
    for p in parts:
        if not p.isdigit():
            return jsonify({"error": f"'{p}' is not a valid port number"}), 400
        n = int(p)
        if not (1 <= n <= 65535):
            return jsonify({"error": f"port {n} is out of range (1-65535)"}), 400
        if n not in ports:
            ports.append(n)
    if not ports:
        return jsonify({"error": "at least one port is required"}), 400

    path = _config_file_path()
    try:
        cfg = {}
        if os.path.exists(path):
            with open(path) as f:
                cfg = _json.load(f)
        cfg["listen_ports"] = ports
        with open(path, "w") as f:
            _json.dump(cfg, f, indent=2)
    except (OSError, ValueError) as exc:
        return jsonify({"error": f"could not write config: {exc}"}), 500
    audit("listen_ports_changed", detail=",".join(map(str, ports)))
    return jsonify({"ok": True, "ports": ports, "restart_required": True})


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Receive logs over HTTP from products that can't send syslog.

    Auth: header 'X-API-Key: <key>' or 'Authorization: Bearer <key>'.
    Body (Content-Type decides):
      * application/json  -> one object, or a list of objects, or
                             {"logs": [...]}. Recognized keys: message/msg,
                             severity/level, hostname/host, app/app_name.
                             Extra scalar keys become key=value for extraction.
      * text/plain        -> one raw syslog line per newline.
    Returns {"ok": true, "ingested": N}.
    """
    _ensure_api_keys_table()
    raw_key = request.headers.get("X-API-Key")
    if not raw_key:
        authz = request.headers.get("Authorization", "")
        if authz.lower().startswith("bearer "):
            raw_key = authz[7:].strip()
    keyrow = _verify_api_key(raw_key)
    if keyrow is None:
        # do not reveal whether the endpoint exists / key format; just 401
        return jsonify({"error": "invalid or missing API key"}), 401

    src = request.headers.get("X-Forwarded-For", request.remote_addr) or "api"
    src = src.split(",")[0].strip()
    ctype = (request.content_type or "").lower()
    count = 0
    try:
        if "application/json" in ctype:
            payload = request.get_json(force=True, silent=True)
            if payload is None:
                return jsonify({"error": "invalid JSON"}), 400
            if isinstance(payload, dict) and "logs" in payload:
                items = payload["logs"]
            elif isinstance(payload, list):
                items = payload
            else:
                items = [payload]
            if not isinstance(items, list):
                return jsonify({"error": "expected an object or list of objects"}), 400
            MAX = 1000
            if len(items) > MAX:
                return jsonify({"error": f"too many logs in one request (max {MAX})"}), 413
            for obj in items:
                if isinstance(obj, dict):
                    line = _json_to_syslog_line(obj)
                else:
                    line = str(obj)
                _ingest_raw(line, src)
                count += 1
        else:
            body = request.get_data(as_text=True) or ""
            for line in body.splitlines():
                if line.strip():
                    _ingest_raw(line, src)
                    count += 1
    except Exception as exc:
        return jsonify({"error": f"ingest failed: {type(exc).__name__}"}), 500
    return jsonify({"ok": True, "ingested": count})


def main():
    global DB_PATH, DB_CONFIG
    ap = argparse.ArgumentParser(description="mini-SIEM dashboard")
    ap.add_argument("--db", default="siem.db")
    ap.add_argument("--db-config", default=None, help="path to db-config.json (sqlite/postgres selector)")
    ap.add_argument("--auth-config", default=None, help="path to auth-config.json (login/OAuth/SAML)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    DB_PATH = args.db
    DB_CONFIG = dbmod.load_config(args.db_config, sqlite_fallback=args.db)
    print(f"[db] backend: {dbmod.describe(DB_CONFIG)}")
    dbmod.initialize(DB_CONFIG)
    init_auth(args.auth_config)
    print("[auth] login enabled; default admin/admin on first run (change forced)")
    start_triage_worker()
    start_automation_workers()
    start_poller_manager()
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
