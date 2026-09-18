import os
import tempfile

import pytest

import dashboard


SPLIT_ROUTES = {
    ("/api/ai/config", "GET"), ("/api/ai/config", "POST"),
    ("/api/ai/test", "POST"), ("/api/ai/usage", "GET"), ("/api/ai/queue/stats", "GET"),
    ("/api/ai/queue/retry", "POST"), ("/api/ai/queue/clear", "POST"),
    ("/api/ai/triage", "POST"), ("/api/ai/chat", "POST"),
    ("/api/health", "GET"), ("/api/db/integrity", "GET"),
    ("/api/db/backup", "POST"),
    ("/api/users", "GET"), ("/api/users", "POST"),
    ("/api/users/<username>", "DELETE"), ("/api/users/password", "POST"),
    ("/api/reports/run", "POST"), ("/api/reports", "GET"),
    ("/api/reports/<int:rid>", "GET"), ("/api/reports/<int:rid>", "DELETE"),
    ("/api/reports/schedule", "GET"), ("/api/reports/schedule", "POST"),
    ("/api/tickets/config", "GET"), ("/api/tickets/config", "POST"),
    ("/api/tickets/test", "POST"),
    ("/api/ioc-feeds", "GET"), ("/api/ioc-feeds", "POST"),
    ("/api/ioc-feeds/<int:fid>/fetch", "POST"),
    ("/api/ioc-feeds/<int:fid>", "PUT"), ("/api/ioc-feeds/<int:fid>", "DELETE"),
}


def _route_methods():
    got = set()
    for rule in dashboard.app.url_map.iter_rules():
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            got.add((rule.rule, method))
    return got


def test_split_route_contract_is_preserved():
    got = _route_methods()
    assert SPLIT_ROUTES <= got


def test_only_requested_blueprints_are_registered():
    names = set(dashboard.app.blueprints)
    assert {"ai_api", "db_health_api", "users_api", "reports_api", "tickets_api", "ioc_feeds_api"} <= names


@pytest.fixture(scope="module")
def initialized_app(tmp_path_factory):
    td = tmp_path_factory.mktemp("dashboard-db")
    dashboard.DB_CONFIG = dashboard.dbmod.config_from_path(str(td / "siem.db"))
    dashboard.init_auth(None)
    return dashboard.app


def test_healthz_remains_public_and_selected_api_remains_guarded(initialized_app):
    client = initialized_app.test_client()
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/ai/config").status_code == 401


def test_csrf_still_blocks_authenticated_state_change(initialized_app):
    client = initialized_app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["must_change"] = False
        sess["csrf_token"] = "expected"
    response = client.post("/api/reports/schedule", json={"schedule": "off"})
    assert response.status_code == 403
