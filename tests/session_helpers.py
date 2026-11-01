"""Disposable real accounts for tests; no production authentication bypass."""
from datetime import datetime, timezone
import auth


def sign_in(dashboard, client, username="admin", role="admin", csrf="t"):
    conn = dashboard.get_conn()
    try:
        if auth.get_user(conn, username):
            conn.execute("UPDATE users SET role=?,must_change_password=0 WHERE username=?", (role, username))
        else:
            conn.execute("INSERT INTO users(username,password_hash,role,auth_source,must_change_password,created_at) VALUES(?,?,?,?,?,?)",
                         (username,"synthetic-test-hash",role,"local",0,datetime.now(timezone.utc).isoformat()))
        conn.commit()
        user = auth.get_user(conn, username)
        with dashboard.app.app_context(): stamp = auth.session_stamp(user)
        with client.session_transaction() as s:
            s.update(user=username,auth_source=user["auth_source"],role=role,
                     auth_stamp=stamp,must_change=False,csrf_token=csrf)
    finally: conn.close()


def set_role(dashboard, client, role):
    with client.session_transaction() as s: username = s["user"]
    conn = dashboard.get_conn()
    try:
        conn.execute("UPDATE users SET role=? WHERE username=?", (role, username)); conn.commit()
    finally: conn.close()
