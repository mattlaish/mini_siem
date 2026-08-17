#!/usr/bin/env bash
#
# mini-SIEM Linux agent installer
# ===============================
# Installs the agent to /opt/mini-siem-agent, writes a config, and runs it
# under systemd as a dedicated unprivileged user.
#
#   sudo ./install-linux-agent.sh --siem-host 10.0.0.10 [--port 514] [--tcp]
#   sudo ./install-linux-agent.sh --siem-host 10.0.0.10 --test-only
#   sudo ./install-linux-agent.sh --uninstall
#
# The agent needs NO root privileges to read journald if its user is in the
# systemd-journal group — which this script arranges. It does not open ports.

set -euo pipefail

SIEM_HOST=""
SIEM_PORT=514
PROTOCOL="udp"
TEST_ONLY=0
UNINSTALL=0

INSTALL_DIR="/opt/mini-siem-agent"
CONFIG_DIR="/etc/mini-siem-agent"
STATE_DIR="/var/lib/mini-siem-agent"
SERVICE="minisiem-agent"
AGENT_USER="minisiem"

usage() { sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --siem-host) SIEM_HOST="$2"; shift 2 ;;
        --port)      SIEM_PORT="$2"; shift 2 ;;
        --tcp)       PROTOCOL="tcp"; shift ;;
        --udp)       PROTOCOL="udp"; shift ;;
        --test-only) TEST_ONLY=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)   usage ;;
        *) echo "unknown option: $1"; usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)"; exit 1; }

# ---- uninstall -----------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    echo "removed agent (config in $CONFIG_DIR and state in $STATE_DIR kept)"
    echo "delete them manually if you want a clean slate."
    exit 0
fi

[ -n "$SIEM_HOST" ] || { echo "--siem-host is required"; usage; }
command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SRC_DIR/minisiem-agent.py" ] || { echo "minisiem-agent.py not found beside this script"; exit 1; }

# ---- user + dirs ---------------------------------------------------------
if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$AGENT_USER"
    echo "created system user $AGENT_USER"
fi
# journald read access without root
if getent group systemd-journal >/dev/null; then
    usermod -a -G systemd-journal "$AGENT_USER"
    echo "added $AGENT_USER to systemd-journal group"
fi

install -d -m 755 "$INSTALL_DIR" "$CONFIG_DIR"
install -d -m 750 -o "$AGENT_USER" -g "$AGENT_USER" "$STATE_DIR"
install -m 755 "$SRC_DIR/minisiem-agent.py" "$INSTALL_DIR/minisiem-agent.py"

# ---- config --------------------------------------------------------------
if [ -f "$CONFIG_DIR/agent-config.json" ]; then
    echo "keeping existing $CONFIG_DIR/agent-config.json (not overwritten)"
else
    cat > "$CONFIG_DIR/agent-config.json" <<EOF
{
  "siem_host": "$SIEM_HOST",
  "siem_port": $SIEM_PORT,
  "protocol": "$PROTOCOL",
  "hostname": "",
  "facility": 16,
  "max_message_bytes": 1800,
  "state_file": "$STATE_DIR/state.json",
  "journald": { "enabled": true, "units": [], "min_priority": 6, "extra_args": [] },
  "files": { "enabled": false, "poll_seconds": 2, "paths": [] },
  "heartbeat_minutes": 15
}
EOF
    chmod 644 "$CONFIG_DIR/agent-config.json"
    echo "wrote $CONFIG_DIR/agent-config.json"
fi

# ---- connectivity test ---------------------------------------------------
echo "sending a test event to $SIEM_HOST:$SIEM_PORT/$PROTOCOL …"
if sudo -u "$AGENT_USER" python3 "$INSTALL_DIR/minisiem-agent.py" \
        --config "$CONFIG_DIR/agent-config.json" --test; then
    echo "test event sent. Check the SIEM's Live logs page for it."
else
    echo "WARNING: test event failed to send. Check firewall/host/port."
    [ "$PROTOCOL" = "udp" ] && echo "         (UDP is fire-and-forget: a 'sent' result does not prove delivery.)"
fi
[ "$TEST_ONLY" -eq 1 ] && exit 0

# ---- systemd unit --------------------------------------------------------
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=mini-SIEM Linux agent
Documentation=https://github.com/your/mini-siem
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$AGENT_USER
Group=$AGENT_USER
SupplementaryGroups=systemd-journal
ExecStart=/usr/bin/python3 $INSTALL_DIR/minisiem-agent.py --config $CONFIG_DIR/agent-config.json
Restart=always
RestartSec=5

# hardening: the agent only reads logs and sends UDP/TCP
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$STATE_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
MemoryMax=128M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 1
systemctl --no-pager --lines=8 status "$SERVICE" || true

cat <<EOF

installed.
  config:   $CONFIG_DIR/agent-config.json
  state:    $STATE_DIR/state.json
  logs:     journalctl -u $SERVICE -f
  stop:     systemctl stop $SERVICE
  remove:   sudo $0 --uninstall

To also tail log files, set files.enabled=true and add paths in the config,
then: systemctl restart $SERVICE
Note: $AGENT_USER must be able to READ any file you add (check permissions).
EOF
