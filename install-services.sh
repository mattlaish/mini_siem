#!/usr/bin/env bash
#
# mini-SIEM two-service systemd installer
# =======================================
# Installs mini-SIEM as TWO systemd services matching the two-process model:
#
#   mini-siem-listener   -> runs listener.py as ROOT (binds syslog port 514)
#   mini-siem-dashboard  -> runs dashboard.py as dedicated SERVICE USER `siem` (Waitress + pollers)
#
# Both start at boot and restart on failure. The dashboard — the only
# network-exposed web surface — never runs as root. The installer creates a
# non-login system account named `siem` for it. The listener stays root only so
# it can bind the privileged syslog port directly.
#
# Python runtime selection / bootstrap:
#   1) <project>/.venv/bin/python3 or python
#   2) <project>/venv/bin/python3 or python (legacy/current deployments)
#   3) if neither project venv is usable, create <project>/.venv and install
#      requirements.txt there. System Python is used only to bootstrap the venv,
#      never as the final service runtime.
#
# CentOS/RHEL SELinux:
# If the project was copied from a home directory into /opt with preserved
# labels, it may still be user_home_t. systemd can then fail with 203/EXEC
# "Permission denied" even though sudo can run Python manually. On an
# Enforcing system and an /opt install, this script safely runs restorecon when
# it detects that stale user_home_t label. It does NOT disable SELinux.
#
# SHARED DATABASE OWNERSHIP
# -------------------------
# The root listener and the `siem` dashboard BOTH write siem.db. This installer:
#   * creates a shared group ("minisiem")
#   * creates the non-login system account `siem` with that primary group
#   * keeps the project code/venv readable but does not make them service-writable
#   * makes the project root + SQLite/config/backup state group-writable
#   * sets setgid on writable directories so SQLite WAL/SHM files inherit the group
#   * uses UMask=0002 in both units
#
# Usage:
#   sudo ./install-services.sh               # install + start
#   sudo ./install-services.sh uninstall     # stop + remove both services
#
# No username/UID argument is required. The dashboard always runs as the
# dedicated `siem` service account.
#
# Run from the permanent mini_siem directory (recommended: /opt/mini_siem).

set -euo pipefail

LISTENER_SVC="mini-siem-listener"
DASHBOARD_SVC="mini-siem-dashboard"
LISTENER_UNIT="/etc/systemd/system/${LISTENER_SVC}.service"
DASHBOARD_UNIT="/etc/systemd/system/${DASHBOARD_SVC}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_GROUP="minisiem"
SERVICE_USER="siem"
SERVICE_HOME="/var/lib/mini-siem"

DASH_HOST="0.0.0.0"
DASH_PORT="8080"
SYSLOG_PORT="514"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 $*" >&2
    exit 1
fi

if [[ "${1:-}" == "uninstall" ]]; then
    for svc in "${DASHBOARD_SVC}" "${LISTENER_SVC}"; do
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
    done
    rm -f "${LISTENER_UNIT}" "${DASHBOARD_UNIT}"
    systemctl daemon-reload
    echo "Removed both mini-SIEM services. Database, files, '${SHARED_GROUP}', and service account '${SERVICE_USER}' were left untouched."
    exit 0
fi

if [[ $# -gt 0 ]]; then
    echo "No username/UID argument is required." >&2
    echo "The dashboard runs as the dedicated '${SERVICE_USER}' service account." >&2
    echo "Usage: sudo $0" >&2
    exit 1
fi

# Select or bootstrap a project-owned virtual environment.  Supporting both
# `.venv` and `venv` lets the installer safely repair older deployments without
# forcing a runtime move.  System Python is only a bootstrap interpreter.
BASE_PYTHON="$(command -v python3 || true)"
PYTHON_BIN=""
for candidate in \
    "${SCRIPT_DIR}/.venv/bin/python3" \
    "${SCRIPT_DIR}/.venv/bin/python" \
    "${SCRIPT_DIR}/venv/bin/python3" \
    "${SCRIPT_DIR}/venv/bin/python"; do
    if [[ -x "${candidate}" ]]; then
        PYTHON_BIN="${candidate}"
        break
    fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
    if [[ -z "${BASE_PYTHON}" || ! -x "${BASE_PYTHON}" ]]; then
        echo "No usable Python 3 interpreter found to bootstrap mini-SIEM." >&2
        exit 1
    fi
    if [[ ! -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        echo "requirements.txt is missing from ${SCRIPT_DIR}." >&2
        exit 1
    fi
    echo "No project venv found; creating ${SCRIPT_DIR}/.venv ..."
    "${BASE_PYTHON}" -m venv "${SCRIPT_DIR}/.venv"
    if [[ -x "${SCRIPT_DIR}/.venv/bin/python3" ]]; then
        PYTHON_BIN="${SCRIPT_DIR}/.venv/bin/python3"
    else
        PYTHON_BIN="${SCRIPT_DIR}/.venv/bin/python"
    fi
fi

if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "Selected Python runtime is not executable: ${PYTHON_BIN}" >&2
    exit 1
fi

# Detect the configured DB backend so PostgreSQL deployments also get the
# psycopg2 driver provisioned (it is an optional dependency, not in
# requirements.txt). Falls back to sqlite if db-config.json is absent/unreadable.
DB_BACKEND="sqlite"
if [[ -f "${SCRIPT_DIR}/db-config.json" ]]; then
    DB_BACKEND="$("${PYTHON_BIN}" - "${SCRIPT_DIR}/db-config.json" <<'PY' 2>/dev/null || echo sqlite
import json, sys
try:
    print((json.load(open(sys.argv[1])).get("backend") or "sqlite").strip().lower())
except Exception:
    print("sqlite")
PY
)"
fi

# Imports every service must satisfy inside the venv. PostgreSQL adds psycopg2.
IMPORT_CHECK="import flask, waitress"
if [[ "${DB_BACKEND}" == "postgres" ]]; then
    IMPORT_CHECK="import flask, waitress, psycopg2"
    echo "db-config.json selects the PostgreSQL backend; psycopg2 will be required."
fi

# Repair missing dependencies inside the selected project venv.  This avoids
# relying on ~/.local site-packages belonging to the administrator who runs sudo.
if ! "${PYTHON_BIN}" -c "${IMPORT_CHECK}" 2>/dev/null; then
    if [[ ! -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        echo "requirements.txt is missing from ${SCRIPT_DIR}." >&2
        exit 1
    fi
    echo "Installing mini-SIEM Python dependencies into $(dirname "$(dirname "${PYTHON_BIN}")") ..."
    if ! "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
        "${PYTHON_BIN}" -m ensurepip --upgrade >/dev/null 2>&1 || true
    fi
    if ! "${PYTHON_BIN}" -m pip install -r "${SCRIPT_DIR}/requirements.txt"; then
        echo "Dependency installation failed for ${PYTHON_BIN}." >&2
        echo "Fix package/network access, then re-run this installer." >&2
        exit 1
    fi
    # PostgreSQL driver is optional and lives outside requirements.txt.
    if [[ "${DB_BACKEND}" == "postgres" ]] && ! "${PYTHON_BIN}" -c "import psycopg2" 2>/dev/null; then
        echo "Installing PostgreSQL driver (psycopg2-binary) ..."
        if ! "${PYTHON_BIN}" -m pip install 'psycopg2-binary>=2.9'; then
            echo "psycopg2-binary installation failed for ${PYTHON_BIN}." >&2
            echo "Install a PostgreSQL client toolchain or psycopg2-binary, then re-run." >&2
            exit 1
        fi
    fi
fi

if ! "${PYTHON_BIN}" -c "${IMPORT_CHECK}" 2>/dev/null; then
    echo "'${PYTHON_BIN}' still cannot import required modules (${IMPORT_CHECK}) after dependency repair." >&2
    exit 1
fi

echo "Using Python: ${PYTHON_BIN}"

for f in listener.py dashboard.py; do
    if [[ ! -f "${SCRIPT_DIR}/${f}" ]]; then
        echo "${f} not found in ${SCRIPT_DIR}. Run this installer from the mini_siem folder." >&2
        exit 1
    fi
done

# CentOS/RHEL: cp -a / mv from a home directory can leave /opt content labeled
# user_home_t. systemd may then be denied EXEC under SELinux Enforcing.
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
    CURRENT_CONTEXT="$(ls -Zd "${SCRIPT_DIR}" 2>/dev/null | awk '{print $1}' || true)"
    PYTHON_CONTEXT="$(ls -Z "${PYTHON_BIN}" 2>/dev/null | awk '{print $1}' || true)"
    if [[ "${SCRIPT_DIR}" == /opt/* && ( "${CURRENT_CONTEXT}" == *":user_home_t:"* || "${PYTHON_CONTEXT}" == *":user_home_t:"* ) ]]; then
        echo "SELinux: stale user_home_t label detected under ${SCRIPT_DIR}; restoring default labels..."
        if command -v restorecon >/dev/null 2>&1; then
            restorecon -RF "${SCRIPT_DIR}"
        else
            echo "restorecon is unavailable. Install policycoreutils and re-run." >&2
            exit 1
        fi
        CURRENT_CONTEXT="$(ls -Zd "${SCRIPT_DIR}" 2>/dev/null | awk '{print $1}' || true)"
        if [[ "${CURRENT_CONTEXT}" == *":user_home_t:"* ]]; then
            cat >&2 <<EOF
SELinux label is still user_home_t after restorecon.
Define a persistent /opt label rule, then retry:
    sudo dnf install -y policycoreutils-python-utils
    sudo semanage fcontext -a -t usr_t '${SCRIPT_DIR}(/.*)?'
    sudo restorecon -RFv '${SCRIPT_DIR}'
If semanage reports that the rule already exists, use -m instead of -a.
Do not disable SELinux for this.
EOF
            exit 1
        fi
        echo "SELinux: restored context to ${CURRENT_CONTEXT}"
    fi
fi

echo "Setting up shared group '${SHARED_GROUP}' and service account '${SERVICE_USER}'..."
getent group "${SHARED_GROUP}" >/dev/null 2>&1 || groupadd --system "${SHARED_GROUP}"

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    NOLOGIN_SHELL="$(command -v nologin || true)"
    if [[ -z "${NOLOGIN_SHELL}" ]]; then
        if [[ -x /usr/sbin/nologin ]]; then
            NOLOGIN_SHELL=/usr/sbin/nologin
        elif [[ -x /sbin/nologin ]]; then
            NOLOGIN_SHELL=/sbin/nologin
        else
            NOLOGIN_SHELL=/bin/false
        fi
    fi
    useradd --system --gid "${SHARED_GROUP}" --home-dir "${SERVICE_HOME}" --no-create-home --shell "${NOLOGIN_SHELL}" "${SERVICE_USER}"
else
    if [[ "$(id -u "${SERVICE_USER}")" == "0" ]]; then
        echo "Refusing to use UID 0 for service account '${SERVICE_USER}'." >&2
        exit 1
    fi
    EXISTING_SHELL="$(getent passwd "${SERVICE_USER}" | cut -d: -f7)"
    case "${EXISTING_SHELL}" in
        */nologin|*/false) ;;
        *)
            echo "Existing user '${SERVICE_USER}' has login shell '${EXISTING_SHELL}'." >&2
            echo "Refusing to repurpose an interactive account as a service account." >&2
            exit 1
            ;;
    esac
    usermod -g "${SHARED_GROUP}" "${SERVICE_USER}"
fi

# Give the service a non-login writable home for libraries that expect HOME,
# without putting mutable state in the code tree.
install -d -o "${SERVICE_USER}" -g "${SHARED_GROUP}" -m 0750 "${SERVICE_HOME}"

# Ensure the dedicated service account can read/execute the deployed code and
# venv even when the tree was copied with restrictive group bits. Do not grant
# group write recursively. SQLite WAL/SHM live beside siem.db, so only the
# project root and explicit runtime state need shared write access.
chgrp -R "${SHARED_GROUP}" "${SCRIPT_DIR}"
chmod -R g+rX "${SCRIPT_DIR}"
chmod 2775 "${SCRIPT_DIR}"

for f in "${SCRIPT_DIR}/db-config.json" "${SCRIPT_DIR}/siem.db" "${SCRIPT_DIR}/siem.db-wal" "${SCRIPT_DIR}/siem.db-shm"; do
    if [[ -e "${f}" ]]; then
        chgrp "${SHARED_GROUP}" "${f}"
        chmod g+rw "${f}"
    fi
done

# Config files can carry secrets (PostgreSQL password, OAuth/SAML credentials).
# Keep them readable by the service group but never world-readable.
for f in "${SCRIPT_DIR}/db-config.json" "${SCRIPT_DIR}/auth-config.json"; do
    if [[ -e "${f}" ]]; then
        chgrp "${SHARED_GROUP}" "${f}"
        chmod 640 "${f}"
    fi
done

if [[ -d "${SCRIPT_DIR}/backups" ]]; then
    chgrp -R "${SHARED_GROUP}" "${SCRIPT_DIR}/backups"
    chmod -R g+rwX "${SCRIPT_DIR}/backups"
    find "${SCRIPT_DIR}/backups" -type d -exec chmod g+s {} \;
fi

# Fail before writing/enabling units if the dedicated account cannot execute
# the selected venv/interpreter or cannot create SQLite WAL/SHM beside siem.db.
if command -v runuser >/dev/null 2>&1; then
    if ! runuser -u "${SERVICE_USER}" -- "${PYTHON_BIN}" -c "${IMPORT_CHECK}" >/dev/null 2>&1; then
        echo "Service account '${SERVICE_USER}' cannot execute '${PYTHON_BIN}' or import required modules (${IMPORT_CHECK})." >&2
        echo "Check venv path permissions and SELinux labels before retrying." >&2
        exit 1
    fi
    # For PostgreSQL, confirm the service account actually resolves the intended
    # backend (readable db-config.json) instead of silently falling back to SQLite.
    if [[ "${DB_BACKEND}" == "postgres" ]]; then
        resolved="$(runuser -u "${SERVICE_USER}" -- "${PYTHON_BIN}" -c \
            "import db; print(db.load_config().get('backend','sqlite'))" 2>/dev/null || echo unknown)"
        if [[ "${resolved}" != "postgres" ]]; then
            echo "Service account '${SERVICE_USER}' resolves DB backend '${resolved}', not 'postgres'." >&2
            echo "It likely cannot read ${SCRIPT_DIR}/db-config.json. Fix ownership/permissions" >&2
            echo "(e.g. chown root:${SHARED_GROUP} db-config.json && chmod 640 db-config.json) and re-run." >&2
            exit 1
        fi
    fi
    if ! runuser -u "${SERVICE_USER}" -- test -w "${SCRIPT_DIR}"; then
        echo "Service account '${SERVICE_USER}' cannot write ${SCRIPT_DIR}; SQLite WAL/SHM creation would fail." >&2
        exit 1
    fi
fi

# Re-running this installer is the supported repair path.  Detect partial
# systemd state explicitly so operators know the installer is reconciling it.
LISTENER_EXISTS=0
DASHBOARD_EXISTS=0
[[ -f "${LISTENER_UNIT}" ]] && LISTENER_EXISTS=1
[[ -f "${DASHBOARD_UNIT}" ]] && DASHBOARD_EXISTS=1
if [[ "${LISTENER_EXISTS}" -ne "${DASHBOARD_EXISTS}" ]]; then
    echo "Partial mini-SIEM service installation detected; repairing both systemd units."
fi

cat > "${LISTENER_UNIT}" <<EOF
[Unit]
Description=mini-SIEM syslog listener (parses + stores events)
After=network.target
Before=${DASHBOARD_SVC}.service

[Service]
Type=simple
User=root
Group=${SHARED_GROUP}
UMask=0002
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/listener.py --db ${SCRIPT_DIR}/siem.db --port ${SYSLOG_PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > "${DASHBOARD_UNIT}" <<EOF
[Unit]
Description=mini-SIEM dashboard (Waitress web UI + API pollers)
After=network.target ${LISTENER_SVC}.service
Wants=${LISTENER_SVC}.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SHARED_GROUP}
UMask=0002
Environment=HOME=${SERVICE_HOME}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/dashboard.py --db ${SCRIPT_DIR}/siem.db --host ${DASH_HOST} --port ${DASH_PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${LISTENER_SVC}" "${DASHBOARD_SVC}"
systemctl reset-failed "${LISTENER_SVC}" "${DASHBOARD_SVC}" 2>/dev/null || true
systemctl restart "${LISTENER_SVC}"
sleep 1
systemctl restart "${DASHBOARD_SVC}"
sleep 2

echo ""
echo "=== ${LISTENER_SVC} ==="
systemctl --no-pager --lines=8 status "${LISTENER_SVC}" || true
echo ""
echo "=== ${DASHBOARD_SVC} ==="
systemctl --no-pager --lines=8 status "${DASHBOARD_SVC}" || true

VERIFY_FAILED=0
for svc in "${LISTENER_SVC}" "${DASHBOARD_SVC}"; do
    if ! systemctl is-enabled --quiet "${svc}"; then
        echo "VERIFY FAIL: ${svc} is not enabled." >&2
        VERIFY_FAILED=1
    fi
    if ! systemctl is-active --quiet "${svc}"; then
        echo "VERIFY FAIL: ${svc} is not active." >&2
        journalctl -u "${svc}" -n 30 --no-pager >&2 || true
        VERIFY_FAILED=1
    fi
done

if ! grep -Fq "ExecStart=${PYTHON_BIN} " "${LISTENER_UNIT}"; then
    echo "VERIFY FAIL: listener unit is not pinned to ${PYTHON_BIN}." >&2
    VERIFY_FAILED=1
fi
if ! grep -Fq "ExecStart=${PYTHON_BIN} " "${DASHBOARD_UNIT}"; then
    echo "VERIFY FAIL: dashboard unit is not pinned to ${PYTHON_BIN}." >&2
    VERIFY_FAILED=1
fi

if command -v ss >/dev/null 2>&1; then
    if ! ss -H -lntup 2>/dev/null | grep -Eq ":${SYSLOG_PORT}([[:space:]]|$)"; then
        echo "VERIFY FAIL: no listener is visible on TCP/UDP ${SYSLOG_PORT}." >&2
        VERIFY_FAILED=1
    fi
    if ! ss -H -lntup 2>/dev/null | grep -Eq ":${DASH_PORT}([[:space:]]|$)"; then
        echo "VERIFY FAIL: no listener is visible on dashboard port ${DASH_PORT}." >&2
        VERIFY_FAILED=1
    fi
fi

if [[ "${VERIFY_FAILED}" -ne 0 ]]; then
    echo "mini-SIEM installation/repair verification FAILED." >&2
    exit 1
fi

echo "Post-install verification: PASS"

cat <<EOF

Installed two services:
  ${LISTENER_SVC}   (root, syslog TCP/UDP port ${SYSLOG_PORT})
  ${DASHBOARD_SVC}  (service user ${SERVICE_USER}, Waitress ${DASH_HOST}:${DASH_PORT})
  Python             ${PYTHON_BIN}

Verify listeners:
  sudo ss -lntup | grep -E ':${SYSLOG_PORT}|:${DASH_PORT}'

Useful commands:
  systemctl --no-pager -l status ${LISTENER_SVC}
  systemctl --no-pager -l status ${DASHBOARD_SVC}
  journalctl -u ${LISTENER_SVC} -n 50 --no-pager
  journalctl -u ${DASHBOARD_SVC} -n 50 --no-pager
  systemctl restart ${LISTENER_SVC} ${DASHBOARD_SVC}
  sudo $0 uninstall

If systemd reports 203/EXEC Permission denied on CentOS/RHEL:
  getenforce
  ls -Zd ${SCRIPT_DIR}
  sudo restorecon -RFv ${SCRIPT_DIR}
The /opt project tree should not remain labeled user_home_t.

Service identity:
  '${SERVICE_USER}' is a non-login system account with primary group '${SHARED_GROUP}'.
  No personal login account or numeric UID needs to be supplied to the installer.

Dashboard: http://${DASH_HOST}:${DASH_PORT}
Database:  ${SCRIPT_DIR}/siem.db
EOF
