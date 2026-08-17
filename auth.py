"""
mini-SIEM authentication
========================
Adds a login layer in front of the dashboard, which otherwise has none.

Three methods, each independently enabled in auth-config.json:

  * local   — username/password stored (hashed) in the DB. Seeds a
              default admin/admin on first run and FORCES a password
              change before anything else can be used.
  * oauth   — OpenID Connect (OAuth2) via Authlib. Works with Google,
              Azure AD/Entra, Okta, Auth0, Keycloak, or any OIDC
              provider that publishes a discovery document.
  * saml    — SAML 2.0 SSO via python3-saml (OneLogin). Works with
              Okta, Azure AD, ADFS, etc.

Local auth needs no extra packages (werkzeug ships with Flask).
OAuth needs:  pip install authlib
SAML  needs:  pip install python3-saml   (plus system libs xmlsec1/libxml2)
Both are imported lazily, so if you only use local auth you install
nothing extra.

SECURITY NOTES
--------------
* Passwords are hashed with werkzeug (pbkdf2). The default admin/admin
  is a first-run bootstrap only — the app refuses to function until it
  is changed.
* OAuth and SAML are implemented with established libraries rather than
  hand-rolled, because incorrect signature/assertion validation is a
  common and severe auth-bypass class. They are config-driven and must
  be tested against your real IdP before you rely on them.
* The session cookie is signed with a secret persisted in the DB
  (auto-generated once). Serve the dashboard over HTTPS in production so
  the cookie can't be sniffed.
"""

import json
import os
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import session, redirect, url_for, request, jsonify

from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DEFAULT_AUTH_CONFIG = {
    "session_secret": "",
    "local_auth": {"enabled": True},
    "oauth": {
        "enabled": False, "provider_name": "SSO", "discovery_url": "",
        "client_id": "", "client_secret": "", "scopes": "openid email profile",
    },
    "saml": {
        "enabled": False, "sp_entity_id": "mini-siem",
        "sp_acs_url": "http://localhost:8080/auth/saml/acs",
        "idp_entity_id": "", "idp_sso_url": "", "idp_x509cert": "",
    },
}


def load_auth_config(config_path: str = None) -> dict:
    candidates = []
    if config_path:
        candidates.append(config_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "auth-config.json"))

    for path in candidates:
        if path and os.path.exists(path):
            with open(path) as f:
                user_cfg = json.load(f)
            merged = json.loads(json.dumps(DEFAULT_AUTH_CONFIG))
            for k, v in user_cfg.items():
                if isinstance(v, dict) and k in merged:
                    merged[k].update(v)
                else:
                    merged[k] = v
            return merged
    return json.loads(json.dumps(DEFAULT_AUTH_CONFIG))


# --------------------------------------------------------------------------
# User store (uses the same db abstraction; table created in db.py schema)
# --------------------------------------------------------------------------

DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"


def seed_default_admin(conn):
    """Create admin/admin on first run, flagged must_change_password."""
    row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    count = row["c"] if isinstance(row, dict) else row[0]
    if count == 0:
        conn.execute(
            """INSERT INTO users (username, password_hash, role, auth_source,
                                  must_change_password, created_at)
               VALUES (?,?,?,?,?,?)""",
            (DEFAULT_ADMIN_USER, generate_password_hash(DEFAULT_ADMIN_PASS),
             "admin", "local", 1, datetime.now(timezone.utc).isoformat()))
        conn.commit()


def get_user(conn, username: str):
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def verify_local(conn, username: str, password: str):
    """Return the user row on success, else None."""
    user = get_user(conn, username)
    if not user:
        return None
    if user["auth_source"] != "local" or not user["password_hash"]:
        return None
    if check_password_hash(user["password_hash"], password):
        return user
    return None


def set_password(conn, username: str, new_password: str):
    conn.execute(
        "UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?",
        (generate_password_hash(new_password), username))
    conn.commit()


def upsert_sso_user(conn, username: str, source: str):
    """Ensure a user record exists for someone authenticated via SSO."""
    if not get_user(conn, username):
        conn.execute(
            """INSERT INTO users (username, password_hash, role, auth_source,
                                  must_change_password, created_at)
               VALUES (?,?,?,?,?,?)""",
            (username, "", "admin", source, 0,
             datetime.now(timezone.utc).isoformat()))
        conn.commit()


# --------------------------------------------------------------------------
# Session helpers + route guard
# --------------------------------------------------------------------------

def get_or_create_secret(conn) -> str:
    """Persist the Flask session secret in app_config so sessions survive
    restarts. Prefers an explicit value from auth-config.json if set."""
    row = conn.execute("SELECT value FROM app_config WHERE key='session_secret'").fetchone()
    if row and row["value"]:
        return row["value"]
    secret = secrets.token_hex(32)
    conn.execute(
        "INSERT INTO app_config(key,value) VALUES('session_secret',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (secret,))
    conn.commit()
    return secret


def current_user():
    return session.get("user")


def current_role():
    """Role of the logged-in user, cached in the session at login.
    Missing/SSO -> 'admin' (preserves prior open behavior for federated
    users; tighten here if SSO users should be restricted)."""
    if not session.get("user"):
        return None
    return session.get("role") or "admin"


def is_admin():
    return current_role() == "admin"


def login_user(username: str, source: str = "local", must_change: bool = False,
               role: str = None):
    session["user"] = username
    session["auth_source"] = source
    session["must_change"] = bool(must_change)
    # SSO users have no local role row -> admin (prior open behavior)
    session["role"] = (role or "admin")


def logout_user():
    session.clear()


# endpoints reachable without being logged in
PUBLIC_ENDPOINTS = {
    "login", "do_login", "logout", "static",
    "oauth_login", "oauth_callback",
    "saml_login", "saml_acs", "saml_metadata",
    "healthz",
}


_CONN_FACTORY = None


def set_conn_factory(factory):
    """Let the host app (dashboard) provide a DB-connection factory so guard
    helpers can read runtime config like the idle-timeout setting."""
    global _CONN_FACTORY
    _CONN_FACTORY = factory


def make_guard(app):
    """Global before_request guard: unauthenticated users are sent to
    /login (pages) or get 401 (api). Logged-in users who still owe a
    password change are pinned to the change-password page. Enforces an
    idle-session timeout when one is configured."""
    import time as _time

    @app.before_request
    def _guard():
        endpoint = request.endpoint or ""
        if endpoint in PUBLIC_ENDPOINTS:
            return None
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))

        # Idle-session timeout: if configured (> 0 minutes) and the gap since
        # the last request exceeds it, log the user out. Value is read from
        # app_config so it's changeable from the UI without a restart.
        idle_limit = _idle_timeout_seconds()
        if idle_limit > 0:
            now = _time.time()
            last = session.get("last_activity")
            if last is not None and (now - last) > idle_limit:
                session.clear()
                if request.path.startswith("/api/"):
                    return jsonify({"error": "session expired due to inactivity"}), 401
                return redirect(url_for("login", next=request.path))
            # Only genuine user activity resets the idle clock. Background
            # auto-refresh polls send X-Background-Poll so they DON'T keep an
            # unattended session alive — the whole point of an idle timeout.
            # (Expiry above is still checked on every request, poll or not.)
            is_background = request.headers.get("X-Background-Poll") == "1"
            if not is_background or last is None:
                session["last_activity"] = now

        # force password change before anything else
        if session.get("must_change") and endpoint not in ("change_password", "do_change_password"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "password change required"}), 403
            return redirect(url_for("change_password"))
        return None


def _idle_timeout_seconds() -> int:
    """Configured idle-session timeout in seconds (0 = disabled). Stored as
    minutes in app_config key 'idle_timeout_minutes'."""
    if _CONN_FACTORY is None:
        return 0
    try:
        conn = _CONN_FACTORY()
        row = conn.execute(
            "SELECT value FROM app_config WHERE key='idle_timeout_minutes'").fetchone()
        conn.close()
        if row and str(row[0]).strip():
            mins = int(float(row[0]))
            return max(0, mins) * 60
    except Exception:
        pass
    return 0


# --------------------------------------------------------------------------
# OAuth / OIDC (Authlib)
# --------------------------------------------------------------------------

def build_oauth(app, cfg: dict):
    """Returns an Authlib OAuth registry with one provider named 'sso',
    or raises RuntimeError with a clear message if misconfigured/missing
    dependency."""
    try:
        from authlib.integrations.flask_client import OAuth
    except ImportError as exc:
        raise RuntimeError("OAuth enabled but Authlib is not installed. Run: pip install authlib") from exc
    o = cfg["oauth"]
    if not o.get("discovery_url") or not o.get("client_id"):
        raise RuntimeError("OAuth enabled but discovery_url/client_id are not set in auth-config.json")
    oauth = OAuth(app)
    oauth.register(
        name="sso",
        client_id=o["client_id"],
        client_secret=o.get("client_secret", ""),
        server_metadata_url=o["discovery_url"],
        client_kwargs={"scope": o.get("scopes", "openid email profile")},
    )
    return oauth


def oauth_identity(token, userinfo) -> str:
    """Extract a stable username from an OIDC token/userinfo."""
    for claim in ("email", "preferred_username", "sub"):
        if userinfo and userinfo.get(claim):
            return userinfo[claim]
    return "sso-user"


# --------------------------------------------------------------------------
# SAML 2.0 (python3-saml)
# --------------------------------------------------------------------------

def _saml_settings(cfg: dict) -> dict:
    s = cfg["saml"]
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": s["sp_entity_id"],
            "assertionConsumerService": {
                "url": s["sp_acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": s["idp_entity_id"],
            "singleSignOnService": {
                "url": s["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": s["idp_x509cert"],
        },
    }


def build_saml_auth(flask_request, cfg: dict):
    """Construct a python3-saml Auth object for the current request, or
    raise RuntimeError with a clear message on missing dep/config."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError as exc:
        raise RuntimeError(
            "SAML enabled but python3-saml is not installed. "
            "Run: pip install python3-saml  (needs system libs xmlsec1/libxml2)."
        ) from exc
    s = cfg["saml"]
    if not s.get("idp_sso_url") or not s.get("idp_x509cert"):
        raise RuntimeError("SAML enabled but idp_sso_url/idp_x509cert are not set in auth-config.json")

    url_data = flask_request
    req = {
        "https": "on" if url_data.scheme == "https" else "off",
        "http_host": url_data.host,
        "server_port": url_data.environ.get("SERVER_PORT"),
        "script_name": url_data.path,
        "get_data": url_data.args.copy(),
        "post_data": url_data.form.copy(),
    }
    return OneLogin_Saml2_Auth(req, _saml_settings(cfg))
