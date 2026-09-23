#!/usr/bin/env bash
#
# mini-SIEM two-service systemd installer
# =======================================
# Installs mini-SIEM as TWO systemd services matching the two-process model:
#
#   mini-siem-listener   -> runs listener.py as `siem-listener` with only CAP_NET_BIND_SERVICE
#   mini-siem-dashboard  -> runs dashboard.py as dedicated SERVICE USER `siem` (Waitress + pollers)
#
# Both start at boot and restart on failure. No long-running mini-SIEM service
# runs as root. The listener binds privileged syslog port 514 using the single
# CAP_NET_BIND_SERVICE capability; PostgreSQL maintenance uses its own non-login
# `siem-maintenance` account.
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
# Operator entry points:
#   sudo ./fresh-install.sh                            # NEW installation only
#   sudo ./upgrade-existing.sh                         # EXISTING installation only
#
# Low-level helper usage (normally called by the entry points):
#   sudo ./install-services.sh                         # reconcile units/permissions + start
#   sudo ./install-services.sh --bootstrap-postgres    # internal fresh PostgreSQL bootstrap
#   sudo ./install-services.sh uninstall               # stop + remove both services
#
# PostgreSQL bootstrap requires MINISIEM_PG_BOOTSTRAP_USER. The administrator
# password is read by tools/postgres_bootstrap.py from a protected environment
# variable or interactive prompt and is never persisted by mini-SIEM.
#
# No username/UID argument is required. The dashboard always runs as the
# dedicated `siem` service account.
#
# Run from the permanent mini_siem directory (recommended: /opt/mini_siem).

set -euo pipefail

LISTENER_SVC="mini-siem-listener"
DASHBOARD_SVC="mini-siem-dashboard"
PARTITION_SVC="mini-siem-event-partitions"
PARTITION_TIMER="mini-siem-event-partitions.timer"
LISTENER_UNIT="/etc/systemd/system/${LISTENER_SVC}.service"
DASHBOARD_UNIT="/etc/systemd/system/${DASHBOARD_SVC}.service"
PARTITION_UNIT="/etc/systemd/system/${PARTITION_SVC}.service"
PARTITION_TIMER_UNIT="/etc/systemd/system/${PARTITION_TIMER}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_GROUP="minisiem"
SERVICE_USER="siem"
LISTENER_USER="siem-listener"
LISTENER_GROUP="minisiem-listener"
MAINTENANCE_USER="siem-maintenance"
MAINTENANCE_GROUP="minisiem-maintenance"
SERVICE_HOME="/var/lib/mini-siem"
FRESH_STATE_PATH="${MINISIEM_FRESH_STATE_PATH:-}"
FRESH_RESUME_SECRET_PATH="${MINISIEM_FRESH_RESUME_SECRET_PATH:-}"
INSTALL_RESUME="${MINISIEM_INSTALL_RESUME:-0}"
AI_SECRET_MASTER="${SERVICE_HOME}/ai-secret-master.key"
CAPTURE_HELPER="/usr/local/libexec/mini-siem-syslog-capture"
CAPTURE_CONFIG_DIR="/etc/mini-siem"
CAPTURE_CONFIG="${CAPTURE_CONFIG_DIR}/syslog-capture.json"
CAPTURE_SUDOERS="/etc/sudoers.d/mini-siem-troubleshoot"

DASH_HOST="0.0.0.0"
DASH_PORT="8080"
SYSLOG_PORT="514"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 $*" >&2
    exit 1
fi

POSTGRES_BOOTSTRAP_REQUESTED=0
if [[ "${1:-}" == "uninstall" ]]; then
    for svc in "${PARTITION_TIMER}" "${PARTITION_SVC}" "${DASHBOARD_SVC}" "${LISTENER_SVC}"; do
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
    done
    rm -f "${LISTENER_UNIT}" "${DASHBOARD_UNIT}" "${PARTITION_UNIT}" "${PARTITION_TIMER_UNIT}"
    rm -f "${CAPTURE_HELPER}" "${CAPTURE_SUDOERS}" "${CAPTURE_CONFIG}"
    rmdir "${CAPTURE_CONFIG_DIR}" 2>/dev/null || true
    systemctl daemon-reload
    echo "Removed both mini-SIEM services. Database, files, '${SHARED_GROUP}', and service account '${SERVICE_USER}' were left untouched."
    exit 0
elif [[ "${1:-}" == "--bootstrap-postgres" && $# -eq 1 ]]; then
    if [[ "${MINISIEM_INSTALL_ENTRYPOINT:-}" != "fresh" ]]; then
        echo "--bootstrap-postgres is an internal fresh-install path." >&2
        echo "Use: sudo ./fresh-install.sh" >&2
        exit 1
    fi
    POSTGRES_BOOTSTRAP_REQUESTED=1
elif [[ $# -gt 0 ]]; then
    echo "No username/UID argument is required." >&2
    echo "The dashboard runs as the dedicated '${SERVICE_USER}' service account." >&2
    echo "Operator install/upgrade entry points: fresh-install.sh or upgrade-existing.sh" >&2
    echo "Low-level usage: sudo $0 [uninstall]" >&2
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

fresh_phase() {
    local phase="$1"
    if [[ "${MINISIEM_INSTALL_ENTRYPOINT:-}" == "fresh" && -n "${FRESH_STATE_PATH}" ]]; then
        "${PYTHON_BIN}" "${SCRIPT_DIR}/tools/fresh_install_state.py" phase             --state "${FRESH_STATE_PATH}" --phase "${phase}" >/dev/null
    fi
}

# Detect the configured DB backend strictly. An explicit deployment must never
# change engines because db-config.json is missing, malformed, or unreadable.
# SQLite is valid only when the configuration explicitly says so.
if [[ ! -f "${SCRIPT_DIR}/db-config.json" ]]; then
    echo "Missing ${SCRIPT_DIR}/db-config.json; run configure-db.py before installation." >&2
    exit 1
fi
DB_BACKEND="$("${PYTHON_BIN}" - "${SCRIPT_DIR}/db-config.json" <<'PY'
import json, sys
path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
except Exception as exc:
    raise SystemExit(f"Invalid database configuration {path}: {exc}")
backend = cfg.get("backend")
if not isinstance(backend, str):
    raise SystemExit("db-config.json is missing backend")
backend = backend.strip().lower()
if backend not in {"sqlite", "postgres"}:
    raise SystemExit(f"unsupported database backend: {backend!r}")
print(backend)
PY
)"

PG_PRIVILEGE_BOUNDARY=0
LISTENER_DB_EXTRA=""
DASHBOARD_DB_EXTRA=""
MAINTENANCE_DB_EXTRA=""
if [[ "${DB_BACKEND}" == "postgres" ]]; then
    PG_PRIVILEGE_BOUNDARY="$("${PYTHON_BIN}" - "${SCRIPT_DIR}/db-config.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    cfg = json.load(fh)
print(1 if (cfg.get("postgres_privilege_boundary") or {}).get("enabled") else 0)
PY
)"
    if [[ "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
        for f in db-listener-credentials.json db-dashboard-credentials.json db-maintenance-credentials.json; do
            if [[ ! -f "${SCRIPT_DIR}/${f}" ]]; then
                echo "PostgreSQL privilege boundary is enabled but ${f} is missing." >&2
                echo "Run: ${PYTHON_BIN} ${SCRIPT_DIR}/tools/postgres_privilege_boundary.py" >&2
                exit 1
            fi
        done
        LISTENER_DB_EXTRA="--db-config ${SCRIPT_DIR}/db-config.json --db-credentials ${SCRIPT_DIR}/db-listener-credentials.json"
        DASHBOARD_DB_EXTRA="--db-config ${SCRIPT_DIR}/db-config.json --db-credentials ${SCRIPT_DIR}/db-dashboard-credentials.json"
        MAINTENANCE_DB_EXTRA="--db-config ${SCRIPT_DIR}/db-config.json --db-credentials ${SCRIPT_DIR}/db-maintenance-credentials.json"
        echo "PostgreSQL privilege boundary: ENABLED (split listener/dashboard/maintenance identities)."
    fi
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

if [[ "${POSTGRES_BOOTSTRAP_REQUESTED}" == "1" ]]; then
    if [[ "${DB_BACKEND}" != "postgres" ]]; then
        echo "--bootstrap-postgres requires db-config.json backend=postgres." >&2
        exit 1
    fi
    if [[ -z "${MINISIEM_PG_BOOTSTRAP_USER:-}" ]]; then
        echo "Set MINISIEM_PG_BOOTSTRAP_USER to the temporary customer PostgreSQL bootstrap identity." >&2
        echo "The password may be supplied via MINISIEM_PG_BOOTSTRAP_PASSWORD or entered interactively." >&2
        exit 1
    fi
    if [[ -z "${FRESH_STATE_PATH}" || -z "${FRESH_RESUME_SECRET_PATH}" ]]; then
        echo "Fresh PostgreSQL bootstrap requires checkpoint state from fresh-install.sh." >&2
        exit 1
    fi
    echo "Running fresh PostgreSQL bootstrap through dedicated migration owner..."
    BOOTSTRAP_ARGS=(
        --mode fresh
        --db-config "${SCRIPT_DIR}/db-config.json"
        --bootstrap-user "${MINISIEM_PG_BOOTSTRAP_USER}"
        --state-file "${FRESH_STATE_PATH}"
        --resume-secrets "${FRESH_RESUME_SECRET_PATH}"
    )
    if [[ "${INSTALL_RESUME}" == "1" ]]; then
        BOOTSTRAP_ARGS+=(--resume)
    fi
    "${PYTHON_BIN}" "${SCRIPT_DIR}/tools/postgres_bootstrap.py" "${BOOTSTRAP_ARGS[@]}"

    # Refresh privilege-boundary state after bootstrap; owner/admin credentials
    # are intentionally absent from the shared runtime config.
    PG_PRIVILEGE_BOUNDARY="$("${PYTHON_BIN}" - "${SCRIPT_DIR}/db-config.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    cfg = json.load(fh)
print(1 if (cfg.get("postgres_privilege_boundary") or {}).get("enabled") else 0)
PY
)"
    if [[ "${PG_PRIVILEGE_BOUNDARY}" != "1" ]]; then
        echo "PostgreSQL bootstrap completed without enabling the runtime privilege boundary; refusing service installation." >&2
        exit 1
    fi
    LISTENER_DB_EXTRA="--db-config ${SCRIPT_DIR}/db-config.json --db-credentials ${SCRIPT_DIR}/db-listener-credentials.json"
    DASHBOARD_DB_EXTRA="--db-config ${SCRIPT_DIR}/db-config.json --db-credentials ${SCRIPT_DIR}/db-dashboard-credentials.json"
    MAINTENANCE_DB_EXTRA="--db-config ${SCRIPT_DIR}/db-config.json --db-credentials ${SCRIPT_DIR}/db-maintenance-credentials.json"
fi

if [[ "${DB_BACKEND}" == "postgres" && "${PG_PRIVILEGE_BOUNDARY}" != "1" ]]; then
    cat >&2 <<EOF
PostgreSQL runtime privilege boundary is not enabled.
mini-SIEM will not install services with a shared owner/runtime credential.

For a new empty database:
  configure db-config.json, then run: sudo -E ${SCRIPT_DIR}/fresh-install.sh

For an existing split-role database:
  extract the new source separately, then run: sudo -E ${SCRIPT_DIR}/upgrade-existing.sh --target /opt/mini_siem

For an existing/legacy database, inspect first; never run fresh bootstrap over operational data:
  ${PYTHON_BIN} ${SCRIPT_DIR}/tools/postgres_bootstrap.py --mode inspect-existing \
    --db-config ${SCRIPT_DIR}/db-config.json --bootstrap-user <customer-admin>
EOF
    exit 1
fi

if [[ "${DB_BACKEND}" == "postgres" && "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
    echo "Validating PostgreSQL schema readiness with runtime credentials before systemd installation..."
    "${PYTHON_BIN}" - "${SCRIPT_DIR}" <<'PY'
import os, sys
root=sys.argv[1]
sys.path.insert(0, root)
import db
for name, cred in (("listener","db-listener-credentials.json"),("dashboard","db-dashboard-credentials.json")):
    cfg=db.load_config(os.path.join(root,"db-config.json"), credentials_path=os.path.join(root,cred))
    db.ensure_runtime_ready(cfg)
    print(f"  {name}: schema/runtime ready")
PY
fi

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

echo "Setting up mini-SIEM service identities..."
getent group "${SHARED_GROUP}" >/dev/null 2>&1 || groupadd --system "${SHARED_GROUP}"
getent group "${LISTENER_GROUP}" >/dev/null 2>&1 || groupadd --system "${LISTENER_GROUP}"
getent group "${MAINTENANCE_GROUP}" >/dev/null 2>&1 || groupadd --system "${MAINTENANCE_GROUP}"

NOLOGIN_SHELL="$(command -v nologin || true)"
if [[ -z "${NOLOGIN_SHELL}" ]]; then
    if [[ -x /usr/sbin/nologin ]]; then NOLOGIN_SHELL=/usr/sbin/nologin
    elif [[ -x /sbin/nologin ]]; then NOLOGIN_SHELL=/sbin/nologin
    else NOLOGIN_SHELL=/bin/false
    fi
fi

ensure_service_identity() {
    local user="$1" primary_group="$2" add_shared="$3"
    if ! id "${user}" >/dev/null 2>&1; then
        useradd --system --gid "${primary_group}" --home-dir "${SERVICE_HOME}"             --no-create-home --shell "${NOLOGIN_SHELL}" "${user}"
    else
        if [[ "$(id -u "${user}")" == "0" ]]; then
            echo "Refusing to use UID 0 for service account '${user}'." >&2
            exit 1
        fi
        local existing_shell
        existing_shell="$(getent passwd "${user}" | cut -d: -f7)"
        case "${existing_shell}" in
            */nologin|*/false) ;;
            *) echo "Existing user '${user}' has interactive shell '${existing_shell}'; refusing to repurpose it." >&2; exit 1 ;;
        esac
        usermod -g "${primary_group}" "${user}"
    fi
    if [[ "${add_shared}" == "1" ]]; then
        usermod -a -G "${SHARED_GROUP}" "${user}"
    fi
}

ensure_service_identity "${SERVICE_USER}" "${SHARED_GROUP}" 0
ensure_service_identity "${LISTENER_USER}" "${LISTENER_GROUP}" 1
ensure_service_identity "${MAINTENANCE_USER}" "${MAINTENANCE_GROUP}" 1

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

# Provision an AI API-key encryption master outside the application database.
# It is owned by the dashboard service account and remains stable across
# service restarts/reinstalls. The database stores only ciphertext.
if [[ ! -f "${AI_SECRET_MASTER}" ]]; then
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "${SERVICE_USER}" -- env HOME="${SERVICE_HOME}" \
            MINISIEM_AI_SECRET_MASTER_FILE="${AI_SECRET_MASTER}" \
            PYTHONPATH="${SCRIPT_DIR}" "${PYTHON_BIN}" -c \
            "import ai_secret; ai_secret.load_or_create_master()"
    else
        env HOME="${SERVICE_HOME}" MINISIEM_AI_SECRET_MASTER_FILE="${AI_SECRET_MASTER}" \
            PYTHONPATH="${SCRIPT_DIR}" "${PYTHON_BIN}" -c \
            "import ai_secret; ai_secret.load_or_create_master()"
    fi
fi
chown "${SERVICE_USER}:${SHARED_GROUP}" "${AI_SECRET_MASTER}"
chmod 600 "${AI_SECRET_MASTER}"

# Base/auth config is readable by the dashboard service group. In secure
# PostgreSQL mode db-config.json is non-secret; component passwords live in
# separate credential files with stricter ownership.
for f in "${SCRIPT_DIR}/db-config.json" "${SCRIPT_DIR}/auth-config.json"; do
    if [[ -e "${f}" ]]; then
        chown root:"${SHARED_GROUP}" "${f}"
        chmod 640 "${f}"
    fi
done
if [[ "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
    chown root:"${LISTENER_GROUP}" "${SCRIPT_DIR}/db-listener-credentials.json"
    chmod 640 "${SCRIPT_DIR}/db-listener-credentials.json"
    chown root:"${MAINTENANCE_GROUP}" "${SCRIPT_DIR}/db-maintenance-credentials.json"
    chmod 640 "${SCRIPT_DIR}/db-maintenance-credentials.json"
    chown root:"${SHARED_GROUP}" "${SCRIPT_DIR}/db-dashboard-credentials.json"
    chmod 640 "${SCRIPT_DIR}/db-dashboard-credentials.json"
fi

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
    # For PostgreSQL, confirm the dashboard account resolves the intended
    # backend and, when enabled, only its own component credential file.
    if [[ "${DB_BACKEND}" == "postgres" ]]; then
        if [[ "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
            resolved="$(runuser -u "${SERVICE_USER}" -- "${PYTHON_BIN}" -c \
                "import db; c=db.load_config('${SCRIPT_DIR}/db-config.json', credentials_path='${SCRIPT_DIR}/db-dashboard-credentials.json'); print(c.get('backend','sqlite'), c.get('_credentials_identity',''))" 2>/dev/null || echo unknown)"
            if [[ "${resolved}" != "postgres dashboard" ]]; then
                echo "Dashboard service account cannot resolve its split PostgreSQL credential: ${resolved}." >&2
                exit 1
            fi
            if runuser -u "${SERVICE_USER}" -- test -r "${SCRIPT_DIR}/db-listener-credentials.json"; then
                echo "VERIFY FAIL: dashboard service account can read listener PostgreSQL credentials." >&2
                exit 1
            fi
            if runuser -u "${SERVICE_USER}" -- test -r "${SCRIPT_DIR}/db-maintenance-credentials.json"; then
                echo "VERIFY FAIL: dashboard service account can read maintenance PostgreSQL credentials." >&2
                exit 1
            fi
            listener_resolved="$(runuser -u "${LISTENER_USER}" -- "${PYTHON_BIN}" -c                 "import db; c=db.load_config('${SCRIPT_DIR}/db-config.json', credentials_path='${SCRIPT_DIR}/db-listener-credentials.json'); print(c.get('backend','sqlite'), c.get('_credentials_identity',''))" 2>/dev/null || echo unknown)"
            if [[ "${listener_resolved}" != "postgres listener" ]]; then
                echo "Listener service account cannot resolve its split PostgreSQL credential: ${listener_resolved}." >&2
                exit 1
            fi
            maintenance_resolved="$(runuser -u "${MAINTENANCE_USER}" -- "${PYTHON_BIN}" -c                 "import db; c=db.load_config('${SCRIPT_DIR}/db-config.json', credentials_path='${SCRIPT_DIR}/db-maintenance-credentials.json'); print(c.get('backend','sqlite'), c.get('_credentials_identity',''))" 2>/dev/null || echo unknown)"
            if [[ "${maintenance_resolved}" != "postgres maintenance" ]]; then
                echo "Maintenance service account cannot resolve its split PostgreSQL credential: ${maintenance_resolved}." >&2
                exit 1
            fi
            for pair in                 "${LISTENER_USER}:${SCRIPT_DIR}/db-dashboard-credentials.json"                 "${LISTENER_USER}:${SCRIPT_DIR}/db-maintenance-credentials.json"                 "${MAINTENANCE_USER}:${SCRIPT_DIR}/db-listener-credentials.json"                 "${MAINTENANCE_USER}:${SCRIPT_DIR}/db-dashboard-credentials.json"; do
                u="${pair%%:*}"; f="${pair#*:}"
                if runuser -u "${u}" -- test -r "${f}"; then
                    echo "VERIFY FAIL: ${u} can read another component PostgreSQL credential: ${f}." >&2
                    exit 1
                fi
            done
        else
            echo "PostgreSQL privilege boundary unexpectedly disabled after preflight." >&2
            exit 1
        fi
    fi
    if ! runuser -u "${SERVICE_USER}" -- test -w "${SCRIPT_DIR}"; then
        echo "Service account '${SERVICE_USER}' cannot write ${SCRIPT_DIR}; SQLite WAL/SHM creation would fail." >&2
        exit 1
    fi
fi

# Install the constrained Setup -> Troubleshoot packet-capture helper outside
# the project tree. It is root-owned so the dashboard account cannot replace
# the executable that sudo is allowed to run.
if [[ ! -f "${SCRIPT_DIR}/tools/syslog_capture_helper.py" ]]; then
    echo "tools/syslog_capture_helper.py is missing from ${SCRIPT_DIR}." >&2
    exit 1
fi
if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required for the constrained syslog troubleshooting capture." >&2
    exit 1
fi
install -d -o root -g root -m 0755 "$(dirname "${CAPTURE_HELPER}")"
install -o root -g root -m 0755 "${SCRIPT_DIR}/tools/syslog_capture_helper.py" "${CAPTURE_HELPER}"
install -d -o root -g root -m 0755 "${CAPTURE_CONFIG_DIR}"
"${PYTHON_BIN}" - "${CAPTURE_CONFIG}" "${SCRIPT_DIR}/db-config.json" <<'CONFIGPY'
import json, os, sys
out, db_config = sys.argv[1], os.path.realpath(sys.argv[2])
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"db_config_path": db_config}, fh, indent=2)
os.chmod(out, 0o600)
CONFIGPY
chown root:root "${CAPTURE_CONFIG}"
cat > "${CAPTURE_SUDOERS}" <<EOF
${SERVICE_USER} ALL=(root) NOPASSWD: ${CAPTURE_HELPER} *
EOF
chmod 0440 "${CAPTURE_SUDOERS}"
chown root:root "${CAPTURE_SUDOERS}"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${CAPTURE_SUDOERS}" >/dev/null
else
    echo "visudo is required to validate ${CAPTURE_SUDOERS}." >&2
    exit 1
fi
if ! command -v tcpdump >/dev/null 2>&1; then
    echo "WARNING: tcpdump is not installed; Setup -> Troubleshoot packet capture will report unavailable."
    echo "On CentOS/RHEL install it with: sudo dnf install -y tcpdump"
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
User=${LISTENER_USER}
Group=${LISTENER_GROUP}
SupplementaryGroups=${SHARED_GROUP}
UMask=0002
Environment=HOME=${SERVICE_HOME}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/listener.py --db ${SCRIPT_DIR}/siem.db --db-config ${SCRIPT_DIR}/db-config.json --port ${SYSLOG_PORT} ${LISTENER_DB_EXTRA}
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${SCRIPT_DIR} ${SERVICE_HOME}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

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
Environment=MINISIEM_AI_SECRET_MASTER_FILE=${AI_SECRET_MASTER}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/dashboard.py --db ${SCRIPT_DIR}/siem.db --db-config ${SCRIPT_DIR}/db-config.json --host ${DASH_HOST} --port ${DASH_PORT} ${DASHBOARD_DB_EXTRA}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

# Event Storage v2 partition lifecycle is PostgreSQL-only.  The timer uses the
# dedicated maintenance database identity and calls only the bounded SECURITY
# DEFINER function; it never receives owner credentials or general DDL rights.
if [[ "${DB_BACKEND}" == "postgres" && "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
    cat > "${PARTITION_UNIT}" <<EOF
[Unit]
Description=mini-SIEM Event Storage v2 partition pre-creation
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${MAINTENANCE_USER}
Group=${MAINTENANCE_GROUP}
SupplementaryGroups=${SHARED_GROUP}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} ${SCRIPT_DIR}/tools/postgres_event_partition_maintenance.py ${MAINTENANCE_DB_EXTRA} --months 3
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

EOF
    cat > "${PARTITION_TIMER_UNIT}" <<EOF
[Unit]
Description=Daily mini-SIEM Event Storage v2 partition pre-creation

[Timer]
OnCalendar=*-*-* 00:17:00
RandomizedDelaySec=15m
Persistent=true
Unit=${PARTITION_SVC}.service

[Install]
WantedBy=timers.target
EOF
else
    systemctl disable --now "${PARTITION_TIMER}" 2>/dev/null || true
    rm -f "${PARTITION_UNIT}" "${PARTITION_TIMER_UNIT}"
fi

fresh_phase SERVICES_INSTALLED
systemctl daemon-reload
systemctl enable "${LISTENER_SVC}" "${DASHBOARD_SVC}"
if [[ "${DB_BACKEND}" == "postgres" && "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
    systemctl enable --now "${PARTITION_TIMER}"
fi
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
if [[ "${DB_BACKEND}" == "postgres" && "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
    if ! systemctl is-enabled --quiet "${PARTITION_TIMER}"; then
        echo "VERIFY FAIL: ${PARTITION_TIMER} is not enabled." >&2
        VERIFY_FAILED=1
    fi
    if ! systemctl is-active --quiet "${PARTITION_TIMER}"; then
        echo "VERIFY FAIL: ${PARTITION_TIMER} is not active." >&2
        VERIFY_FAILED=1
    fi
fi
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
if [[ ! -f "${AI_SECRET_MASTER}" ]] || [[ "$(stat -c '%a' "${AI_SECRET_MASTER}" 2>/dev/null || echo bad)" != "600" ]]; then
    echo "VERIFY FAIL: AI secret master is missing or not mode 0600: ${AI_SECRET_MASTER}." >&2
    VERIFY_FAILED=1
fi
if command -v runuser >/dev/null 2>&1 && ! runuser -u "${SERVICE_USER}" -- test -r "${AI_SECRET_MASTER}"; then
    echo "VERIFY FAIL: dashboard service account cannot read AI secret master." >&2
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

if ! grep -Fq "User=${LISTENER_USER}" "${LISTENER_UNIT}" || ! grep -Fq "AmbientCapabilities=CAP_NET_BIND_SERVICE" "${LISTENER_UNIT}"; then
    echo "VERIFY FAIL: listener is not running as ${LISTENER_USER} with CAP_NET_BIND_SERVICE." >&2
    VERIFY_FAILED=1
fi
if [[ "${DB_BACKEND}" == "postgres" && "${PG_PRIVILEGE_BOUNDARY}" == "1" ]]; then
    if ! grep -Fq "User=${MAINTENANCE_USER}" "${PARTITION_UNIT}"; then
        echo "VERIFY FAIL: PostgreSQL partition maintenance is not using ${MAINTENANCE_USER}." >&2
        VERIFY_FAILED=1
    fi
fi

if [[ "${VERIFY_FAILED}" -ne 0 ]]; then
    echo "mini-SIEM installation/repair verification FAILED." >&2
    exit 1
fi

fresh_phase OPERATIONAL
if [[ "${MINISIEM_INSTALL_ENTRYPOINT:-}" == "fresh" && -n "${FRESH_RESUME_SECRET_PATH}" ]]; then
    rm -f "${FRESH_RESUME_SECRET_PATH}"
fi

echo "Post-install verification: PASS"

cat <<EOF

Installed two services:
  ${LISTENER_SVC}   (service user ${LISTENER_USER}, CAP_NET_BIND_SERVICE, syslog TCP/UDP ${SYSLOG_PORT})
  ${DASHBOARD_SVC}  (service user ${SERVICE_USER}, Waitress ${DASH_HOST}:${DASH_PORT})
  Event partitions    ${PARTITION_TIMER} (PostgreSQL split-role deployments only)
  Python             ${PYTHON_BIN}
  AI secret master    ${AI_SECRET_MASTER} (0600, outside DB)

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
  '${SERVICE_USER}', '${LISTENER_USER}', and '${MAINTENANCE_USER}' are non-login system accounts.
  No personal login account or numeric UID needs to be supplied to the installer.

Dashboard: http://${DASH_HOST}:${DASH_PORT}
Database:  ${SCRIPT_DIR}/siem.db
EOF
