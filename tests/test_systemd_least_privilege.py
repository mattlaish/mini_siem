from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_listener_runs_nonroot_with_only_bind_capability():
    text = (ROOT / "install-services.sh").read_text()
    listener = text.split('cat > "${LISTENER_UNIT}" <<EOF', 1)[1].split('cat > "${DASHBOARD_UNIT}" <<EOF', 1)[0]
    assert "User=${LISTENER_USER}" in listener
    assert "User=root" not in listener
    assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in listener
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in listener
    assert "NoNewPrivileges=true" in listener
    assert "ProtectSystem=strict" in listener


def test_partition_maintenance_runs_nonroot_and_credentials_are_separated():
    text = (ROOT / "install-services.sh").read_text()
    part = text.split('cat > "${PARTITION_UNIT}" <<EOF', 1)[1].split('cat > "${PARTITION_TIMER_UNIT}" <<EOF', 1)[0]
    assert "User=${MAINTENANCE_USER}" in part
    assert "User=root" not in part
    assert 'chown root:"${LISTENER_GROUP}" "${SCRIPT_DIR}/db-listener-credentials.json"' in text
    assert 'chown root:"${MAINTENANCE_GROUP}" "${SCRIPT_DIR}/db-maintenance-credentials.json"' in text
    assert "another component PostgreSQL credential" in text


def test_dashboard_and_maintenance_drop_capability_bounding_set():
    text = (ROOT / "install-services.sh").read_text()
    dashboard = text.split('cat > "${DASHBOARD_UNIT}" <<EOF', 1)[1].split('# Event Storage v2 partition lifecycle', 1)[0]
    assert "User=${SERVICE_USER}" in dashboard
    assert "NoNewPrivileges=true" in dashboard
    assert "CapabilityBoundingSet=" in dashboard

    part = text.split('cat > "${PARTITION_UNIT}" <<EOF', 1)[1].split('cat > "${PARTITION_TIMER_UNIT}" <<EOF', 1)[0]
    assert "NoNewPrivileges=true" in part
    assert "CapabilityBoundingSet=" in part
