#!/usr/bin/env bash
#
# mini-SIEM systemd service installer
# ====================================
# Registers mini-SIEM (listener + dashboard, via siem.py) as a systemd
# service that starts at boot and restarts automatically on failure.
#
# Usage:
#     sudo ./install-service.sh              # install + start
#     sudo ./install-service.sh uninstall    # stop + remove
#
# The service runs siem.py from THIS directory — move the folder first
# if you want it somewhere permanent (e.g. /opt/mini_siem), then run
# the installer from there.

set -euo pipefail

SERVICE_NAME="mini-siem"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$(command -v python3)"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 $*" >&2
    exit 1
fi

if [[ "${1:-}" == "uninstall" ]]; then
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${UNIT_FILE}"
    systemctl daemon-reload
    echo "Removed ${SERVICE_NAME} service. Files and database were left untouched."
    exit 0
fi

if [[ ! -f "${SCRIPT_DIR}/siem.py" ]]; then
    echo "siem.py not found next to this script (${SCRIPT_DIR}). Run the installer from the mini_siem folder." >&2
    exit 1
fi

# Sanity check: Flask available to the python that systemd will use?
if ! "${PYTHON_BIN}" -c "import flask" 2>/dev/null; then
    echo "WARNING: '${PYTHON_BIN}' cannot import flask." >&2
    echo "Install it first (pip install -r requirements.txt, with --break-system-packages" >&2
    echo "on newer Debian/Ubuntu, or point the unit at a venv python), then re-run." >&2
    exit 1
fi

cat > "${UNIT_FILE}" << EOF
[Unit]
Description=mini-SIEM (syslog listener + dashboard)
After=network.target

[Service]
Type=simple
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/siem.py --db ${SCRIPT_DIR}/siem.db
WorkingDirectory=${SCRIPT_DIR}
Restart=on-failure
RestartSec=3
# root is required to bind port 514 directly; see README section 2 for
# non-root alternatives (setcap / port redirect), then set User= here.
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 1
systemctl --no-pager --lines=5 status "${SERVICE_NAME}" || true

cat << EOF

Installed. Useful commands:
  systemctl status ${SERVICE_NAME}        service state
  journalctl -u ${SERVICE_NAME} -f        live logs (incoming events, alerts, forwarder activity)
  systemctl restart ${SERVICE_NAME}       restart after updating code
  sudo $0 uninstall                       remove the service

Dashboard: http://127.0.0.1:8080 (on this machine; use an SSH tunnel from elsewhere)
Database:  ${SCRIPT_DIR}/siem.db
EOF
