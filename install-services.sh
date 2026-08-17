#!/usr/bin/env bash
#
# mini-SIEM two-service systemd installer
# =======================================
# Installs mini-SIEM as TWO systemd services matching the two-process model:
#
#   mini-siem-listener   -> runs listener.py as ROOT (binds syslog port 514)
#   mini-siem-dashboard  -> runs dashboard.py as an UNPRIVILEGED USER (web UI + poller)
#
# Both start at boot and restart on failure. The dashboard — the only
# network-exposed web surface — never runs as root, which is where most of
# the security benefit is. The listener stays root only so it can bind the
# privileged syslog port without extra setup.
#
# SHARED DATABASE OWNERSHIP
# -------------------------
# The root listener and the user dashboard BOTH write siem.db. Without care
# this causes "attempt to write a readonly database" on the dashboard side.
# This installer solves it by:
#   * creating a shared group ("minisiem")
#   * adding the dashboard user to it
#   * making the DB files group-owned and group-writable
#   * setting the listener unit's UMask so new DB files stay group-writable
#
# Usage:
#   sudo ./install-services.sh [USER]        # install + start (USER defaults to the invoking sudo user)
#   sudo ./install-services.sh uninstall     # stop + remove both services
#
# Run this from the mini_siem folder (or move the folder somewhere permanent
# like /opt/mini_siem first, then run it from there).

set -euo pipefail

LISTENER_SVC="mini-siem-listener"
DASHBOARD_SVC="mini-siem-dashboard"
LISTENER_UNIT="/etc/systemd/system/${LISTENER_SVC}.service"
DASHBOARD_UNIT="/etc/systemd/system/${DASHBOARD_SVC}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$(command -v python3)"
SHARED_GROUP="minisiem"

# --- dashboard listen address/port (edit if you want) -------------------------
DASH_HOST="0.0.0.0"
DASH_PORT="8080"
# syslog listen port for the listener
SYSLOG_PORT="514"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 $*" >&2
    exit 1
fi

# ---- uninstall ---------------------------------------------------------------
if [[ "${1:-}" == "uninstall" ]]; then
    for svc in "${DASHBOARD_SVC}" "${LISTENER_SVC}"; do
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
    done
    rm -f "${LISTENER_UNIT}" "${DASHBOARD_UNIT}"
    systemctl daemon-reload
    echo "Removed both mini-SIEM services. Database, files, and the '${SHARED_GROUP}' group were left untouched."
    echo "(To remove the group later: sudo groupdel ${SHARED_GROUP})"
    exit 0
fi

# ---- determine the dashboard user -------------------------------------------
# Default to the user who invoked sudo; allow override as $1.
DASH_USER="${1:-${SUDO_USER:-}}"
if [[ -z "${DASH_USER}" || "${DASH_USER}" == "root" ]]; then
    echo "Refusing to run the dashboard as root. Pass a non-root user:" >&2
    echo "    sudo $0 <username>" >&2
    exit 1
fi
if ! id "${DASH_USER}" >/dev/null 2>&1; then
    echo "User '${DASH_USER}' does not exist." >&2
    exit 1
fi

# ---- sanity: files present + flask importable --------------------------------
for f in listener.py dashboard.py; do
    if [[ ! -f "${SCRIPT_DIR}/${f}" ]]; then
        echo "${f} not found in ${SCRIPT_DIR}. Run the installer from the mini_siem folder." >&2
        exit 1
    fi
done
if ! "${PYTHON_BIN}" -c "import flask" 2>/dev/null; then
    echo "WARNING: '${PYTHON_BIN}' cannot import flask." >&2
    echo "Install it (pip install -r requirements.txt --break-system-packages), then re-run." >&2
    exit 1
fi

# ---- shared group + DB ownership so BOTH users can write ---------------------
echo "Setting up shared group '${SHARED_GROUP}' for DB access..."
getent group "${SHARED_GROUP}" >/dev/null 2>&1 || groupadd "${SHARED_GROUP}"
usermod -aG "${SHARED_GROUP}" "${DASH_USER}"
# root is always able to write; the dashboard user needs the group.

# The whole working dir should be group-owned so new WAL/SHM files inherit it.
chgrp -R "${SHARED_GROUP}" "${SCRIPT_DIR}"
chmod -R g+rw "${SCRIPT_DIR}"
# setgid on the dir => new files created inside inherit the group automatically
find "${SCRIPT_DIR}" -type d -exec chmod g+s {} \;

# If a DB already exists, make sure it's group-writable right now.
for f in "${SCRIPT_DIR}"/siem.db "${SCRIPT_DIR}"/siem.db-wal "${SCRIPT_DIR}"/siem.db-shm; do
    [[ -e "$f" ]] && chgrp "${SHARED_GROUP}" "$f" && chmod g+rw "$f" || true
done

# ---- listener unit (root, binds 514) ----------------------------------------
# UMask 0002 => files the root listener creates are group-writable, so the
# dashboard user (in the shared group) can also write them.
cat > "${LISTENER_UNIT}" << EOF
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

# ---- dashboard unit (unprivileged user, web UI + poller) --------------------
cat > "${DASHBOARD_UNIT}" << EOF
[Unit]
Description=mini-SIEM dashboard (web UI + API pollers)
After=network.target ${LISTENER_SVC}.service
Wants=${LISTENER_SVC}.service

[Service]
Type=simple
User=${DASH_USER}
Group=${SHARED_GROUP}
UMask=0002
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/dashboard.py --db ${SCRIPT_DIR}/siem.db --host ${DASH_HOST} --port ${DASH_PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${LISTENER_SVC}" "${DASHBOARD_SVC}"
systemctl restart "${LISTENER_SVC}"
sleep 1
systemctl restart "${DASHBOARD_SVC}"
sleep 1

echo ""
echo "=== ${LISTENER_SVC} ==="
systemctl --no-pager --lines=4 status "${LISTENER_SVC}" || true
echo ""
echo "=== ${DASHBOARD_SVC} ==="
systemctl --no-pager --lines=4 status "${DASHBOARD_SVC}" || true

cat << EOF

Installed two services:
  ${LISTENER_SVC}   (root, syslog port ${SYSLOG_PORT})
  ${DASHBOARD_SVC}  (user ${DASH_USER}, web UI ${DASH_HOST}:${DASH_PORT})

Useful commands:
  systemctl status ${LISTENER_SVC}
  systemctl status ${DASHBOARD_SVC}
  journalctl -u ${LISTENER_SVC} -f      # live listener logs (incoming events)
  journalctl -u ${DASHBOARD_SVC} -f     # live dashboard logs (poller, web)
  systemctl restart ${LISTENER_SVC} ${DASHBOARD_SVC}   # after updating code
  sudo $0 uninstall                     # remove both services

IMPORTANT — group membership:
  '${DASH_USER}' was added to the '${SHARED_GROUP}' group so the dashboard can
  write the shared database. If ${DASH_USER} is currently logged in elsewhere,
  that session must log out/in (or reboot) for the group to take effect for
  interactive use. The systemd service already picks it up on restart.

Dashboard: http://${DASH_HOST}:${DASH_PORT}
Database:  ${SCRIPT_DIR}/siem.db  (group '${SHARED_GROUP}', group-writable)
EOF
