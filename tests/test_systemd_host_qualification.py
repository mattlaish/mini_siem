from pathlib import Path
import json

from tools import systemd_host_qualification as q


ROOT = Path(__file__).resolve().parents[1]


def test_installer_uses_dedicated_dashboard_group_and_isolated_credentials():
    text = (ROOT / "install-services.sh").read_text()
    assert 'DASHBOARD_GROUP="minisiem-dashboard"' in text
    assert 'ensure_service_identity "${SERVICE_USER}" "${DASHBOARD_GROUP}" 1' in text
    assert 'Group=${DASHBOARD_GROUP}' in text
    assert 'SupplementaryGroups=${SHARED_GROUP}' in text
    assert 'chown root:"${DASHBOARD_GROUP}" "${SCRIPT_DIR}/db-dashboard-credentials.json"' in text
    assert 'chown root:"${DASHBOARD_GROUP}" "${SCRIPT_DIR}/auth-config.json"' in text


def test_postgres_source_tree_is_made_runtime_immutable():
    text = (ROOT / "install-services.sh").read_text()
    assert 'if [[ "${DB_BACKEND}" == "postgres" ]]; then' in text
    assert 'chmod -R g-w "${SCRIPT_DIR}"' in text
    assert 'chmod 2755 "${SCRIPT_DIR}"' in text
    assert 'source tree ${SCRIPT_DIR}' in text
    assert 'LISTENER_READWRITE_PATHS="${SERVICE_HOME}"' in text
    assert 'ReadWritePaths=${LISTENER_READWRITE_PATHS}' in text
    assert 'Environment=PYTHONDONTWRITEBYTECODE=1' in text


def test_postgres_archive_must_not_be_inside_source_tree():
    text = (ROOT / "install-services.sh").read_text()
    assert 'PostgreSQL archive state must live outside the application source tree.' in text
    assert 'Configure archive.directory as an absolute mutable-state path' in text
    assert 'install -d -o "${LISTENER_USER}" -g "${SHARED_GROUP}" -m 2750 "${ARCHIVE_DIR}"' in text


def test_parse_systemctl_show():
    parsed = q.parse_systemctl_show("User=siem-listener\nNoNewPrivileges=yes\nMainPID=123\n")
    assert parsed == {"User": "siem-listener", "NoNewPrivileges": "yes", "MainPID": "123"}


def test_reboot_check_requires_changed_boot_id(tmp_path, monkeypatch):
    baseline = tmp_path / "before.json"
    baseline.write_text(json.dumps({"host": {"boot_id": "old-boot"}}))

    real_read_text = Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if str(self) == "/proc/sys/kernel/random/boot_id":
            return "new-boot\n"
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)
    checks = q.reboot_checks("post-reboot", baseline)
    changed = next(c for c in checks if c["name"] == "reboot:boot-id-changed")
    assert changed["ok"] is True


def test_systemd_host_runner_is_read_only_contract():
    text = (ROOT / "tools" / "systemd_host_qualification.py").read_text()
    forbidden = ["systemctl restart", "systemctl stop", "systemctl start", "systemctl enable", "chmod ", "chown ", "useradd ", "groupadd "]
    for needle in forbidden:
        assert needle not in text
    assert '"BLOCKED_ENVIRONMENT"' in text
    assert '"post-reboot"' in text
    assert 'CapEff:' in text
    assert 'CapAmb:' in text
