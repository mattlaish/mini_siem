#!/usr/bin/env python3
"""
mini-SIEM dynamic security scanner
==================================
Launches the dashboard against a TEMPORARY throwaway database and probes it
live for: broken access control, SQL injection, weak input validation, XSS
reflection, missing response-hardening headers, insecure session cookies, and
secret leakage. Nothing touches your real siem.db.

Zero external dependencies — uses Flask's built-in test client (Flask is
already a project dependency; no requests/pytest needed).

Run this from the mini_siem folder (so the project modules import):

    python3 security_dynamic_scan.py

It creates /tmp/secscan_dynamic.db, exercises the app, prints PASS/FAIL per
check, and a summary. Safe to run repeatedly. Exit code is non-zero if any
check fails, so you can wire it into a pre-deploy check if you like.

WHY A TEMP DB: the scan logs in with the default admin/admin, rotates the
password, and fires attack payloads (including a DROP TABLE attempt). You do
NOT want that against production data. The temp DB is deleted and recreated
each run.
"""
import os
import sys
import json
import tempfile


def build_client():
    """Import the app, point it at a fresh temp DB, return a logged-in and a
    fresh (anonymous) test client."""
    try:
        import db
        import dashboard
    except ImportError as e:
        print("ERROR: run this from the mini_siem folder so project modules "
              f"import (missing: {e}).", file=sys.stderr)
        sys.exit(2)

    dbp = os.path.join(tempfile.gettempdir(), "secscan_dynamic.db")
    for ext in ("", "-wal", "-shm"):
        try:
            os.remove(dbp + ext)
        except OSError:
            pass
    db.initialize(db.config_from_path(dbp))
    dashboard.DB_CONFIG = db.config_from_path(dbp)
    dashboard.init_auth("auth-config.json")
    return dashboard, dbp


class Results:
    def __init__(self):
        self.items = []

    def check(self, name, passed, detail=""):
        self.items.append((bool(passed), name, detail))
        print(f"[{'PASS' if passed else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""))

    def summary(self):
        p = sum(1 for x in self.items if x[0])
        f = len(self.items) - p
        print("\n" + "=" * 72)
        print(f"RESULTS: {p} passed, {f} failed, {len(self.items)} total")
        if f:
            print("\nFailures:")
            for ok, name, detail in self.items:
                if not ok:
                    print(f"  - {name} ({detail})")
        print("=" * 72)
        return f


def run():
    dashboard, dbp = build_client()
    r = Results()
    anon = dashboard.app.test_client()

    print("=" * 72)
    print("DYNAMIC SECURITY SCAN — mini-SIEM")
    print(f"(temp db: {dbp})")
    print("=" * 72)

    # 1. ACCESS CONTROL — protected endpoints must reject anonymous access
    print("\n-- Access control (unauthenticated) --")
    protected = ["/api/logs", "/api/stats", "/api/profiles",
                 "/api/normalization-overview", "/api/audit",
                 "/api/log-fields/1", "/api/forwarders", "/api/pollers", "/setup"]
    for ep in protected:
        resp = anon.get(ep)
        blocked = resp.status_code in (301, 302, 401, 403)
        r.check(f"anon blocked: {ep}", blocked, f"status {resp.status_code}")
    resp = anon.get("/", follow_redirects=False)
    r.check("anon / redirects to login", resp.status_code in (301, 302),
            f"status {resp.status_code}")

    # Five failures for one IP+username are allowed; the next is rejected.
    limiter = dashboard.app.test_client()
    for _ in range(5):
        limiter.post("/login", data={"username": "_missing_scan_user",
                                      "password": "wrong"},
                     headers={"X-Forwarded-For": "192.0.2.10"})
    limited = limiter.post("/login", data={"username": "_missing_scan_user",
                                            "password": "wrong"},
                           headers={"X-Forwarded-For": "192.0.2.10"})
    r.check("login failures rate limited", limited.status_code == 429,
            f"status {limited.status_code}")
    r.check("login limiter sends Retry-After", bool(limited.headers.get("Retry-After")),
            limited.headers.get("Retry-After", "missing"))

    # authenticate (default creds, then rotate as the app forces)
    c = dashboard.app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin"},
           follow_redirects=True)
    with c.session_transaction() as sess:
        csrf_token = sess["csrf_token"]
    csrf_headers = {"Origin": "http://localhost", "X-CSRF-Token": csrf_token}
    c.post("/auth/change-password",
           data={"current_password": "admin", "new_password": "S3cure!!x",
                  "confirm_password": "S3cure!!x", "csrf_token": csrf_token},
           headers={"Origin": "http://localhost"}, follow_redirects=True)

    # CSRF — authenticated state changes need both the session token and,
    # when configured, an explicitly allowed Origin.
    print("\n-- CSRF protection --")
    probe = "/api/ai/queue/retry"
    resp = c.post(probe)
    r.check("CSRF missing token rejected", resp.status_code == 403,
            f"status {resp.status_code}")
    resp = c.post(probe, headers={"Origin": "http://localhost",
                                  "X-CSRF-Token": "wrong"})
    r.check("CSRF wrong token rejected", resp.status_code == 403,
            f"status {resp.status_code}")
    old_origin = os.environ.get("MINISIEM_ALLOWED_ORIGIN")
    os.environ["MINISIEM_ALLOWED_ORIGIN"] = "http://localhost"
    resp = c.post(probe, headers={"Origin": "https://evil.example",
                                  "X-CSRF-Token": csrf_token})
    r.check("CSRF wrong Origin rejected", resp.status_code == 403,
            f"status {resp.status_code}")
    resp = c.post(probe, headers=csrf_headers)
    r.check("CSRF valid token and Origin accepted", resp.status_code == 200,
            f"status {resp.status_code}")
    if old_origin is None:
        os.environ.pop("MINISIEM_ALLOWED_ORIGIN", None)
    else:
        os.environ["MINISIEM_ALLOWED_ORIGIN"] = old_origin

    # 2. SQL INJECTION — payloads must be treated as literals
    print("\n-- SQL injection (authenticated) --")
    payloads = ["' OR '1'='1", "'; DROP TABLE logs;--",
                "1' UNION SELECT null--", '" OR ""="']
    for pl in payloads:
        resp = c.get("/api/logs", query_string={"source": pl, "limit": 5})
        ok = resp.status_code == 200
        try:
            ok = ok and isinstance(resp.get_json(), list)
        except Exception:
            ok = False
        r.check(f"SQLi handled: {pl[:20]}", ok, f"status {resp.status_code}")
    resp = c.get("/api/logs?limit=1")
    r.check("logs table intact after DROP attempt", resp.status_code == 200)
    for pl in ["x=' OR 1=1--", "x=1;DELETE FROM logs"]:
        resp = c.get(f"/api/logs?{pl}&limit=5")
        r.check(f"field-filter SQLi handled: {pl[:18]}",
                resp.status_code == 200, f"status {resp.status_code}")

    # 3. INPUT VALIDATION — bad IDs / traversal rejected
    print("\n-- Input validation --")
    for bad in ["/api/log-fields/../../etc/passwd",
                "/api/log-fields/1;ls", "/api/log-fields/abc"]:
        resp = anon_or(c, bad)
        r.check(f"rejects bad id: {bad.split('/')[-1][:15]}",
                resp.status_code in (400, 404), f"status {resp.status_code}")

    # 4. XSS reflection
    resp = c.get("/api/logs?source=<script>alert(1)</script>&limit=1")
    body = resp.get_data(as_text=True)
    r.check("no reflected raw <script>",
            "<script>alert(1)</script>" not in body)

    # 5. RESPONSE HARDENING HEADERS
    print("\n-- Response hardening --")
    resp = c.get("/login")
    h = resp.headers
    r.check("X-Content-Type-Options present",
            "X-Content-Type-Options" in h, h.get("X-Content-Type-Options", "MISSING"))
    r.check("Frame protection present",
            "X-Frame-Options" in h or "Content-Security-Policy" in h,
            h.get("X-Frame-Options", h.get("Content-Security-Policy", "MISSING")))

    # 6. SESSION COOKIE FLAGS — check on the response that SETS the cookie
    print("\n-- Session cookie --")
    fresh = dashboard.app.test_client()
    login_resp = fresh.post("/login", data={"username": "admin",
                                            "password": "S3cure!!x"})
    set_cookie = login_resp.headers.get("Set-Cookie", "")
    r.check("session cookie HttpOnly", "HttpOnly" in set_cookie,
            "checked login Set-Cookie")
    r.check("session cookie SameSite", "SameSite" in set_cookie,
            "checked login Set-Cookie")

    # 7. SECRET LEAKAGE — poller secrets never returned
    print("\n-- Secret handling --")
    resp = c.get("/api/pollers")
    b = resp.get_data(as_text=True).replace(" ", "").lower()
    r.check("poller list excludes client_secret",
            "client_secret" not in b or '"client_secret":null' in b)
    resp = c.post("/api/ioc-feeds", json={"name": "_scan_probe", "url": "https://example.com/x",
                                          "auth_scheme": "header", "header_name": "X-Key",
                                          "key": "PROBE_SECRET_VALUE"},
                  headers=csrf_headers)
    resp2 = c.get("/api/ioc-feeds")
    b2 = resp2.get_data(as_text=True)
    r.check("ioc-feeds list excludes stored key",
            "PROBE_SECRET_VALUE" not in b2 and "key_encrypted" not in b2)

    return r.summary()


def anon_or(client, url):
    """GET a URL with the authenticated client (bad-id checks don't depend on
    auth state, but using the logged-in client avoids a redirect masking the
    real status)."""
    return client.get(url)


if __name__ == "__main__":
    fails = run()
    sys.exit(1 if fails else 0)
