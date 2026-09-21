#!/usr/bin/env bash
# Existing-installation upgrade entry point for mini-SIEM.
#
# This script is intentionally NOT a fresh bootstrap path. It preserves
# existing runtime DB credentials, config, state and secrets, creates an
# external rollback tree/DB backup, applies owner-only PostgreSQL migrations,
# and performs an atomic-ish source-tree cutover at the stable target path.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/opt/mini_siem"
BACKUP_ROOT="/var/backups/mini-siem"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
CURRENT_STAGE="preflight"
RESOLVED_OWNER=""
PG_DUMP_METHOD=""
PG_DUMP_CLIENT_VERSION=""
PG_SERVER_VERSION=""

set_stage() {
  CURRENT_STAGE="$1"
  echo "==> Upgrade stage: ${CURRENT_STAGE}"
}

usage() {
  cat <<EOF
Usage: sudo $0 [--target /opt/mini_siem] [--backup-root /var/backups/mini-siem]

Existing installation only. Run this script from a separately extracted NEW
mini-SIEM source package. It refuses to run in-place from the current target.

For split-role PostgreSQL upgrades the schema owner credential is temporary:
  MINISIEM_PG_OWNER_USER=auto-discovered      # optional override for legacy owner
  MINISIEM_PG_OWNER_PASSWORD=...               # optional; otherwise TTY prompt

This path NEVER calls fresh PostgreSQL bootstrap and NEVER rotates the existing
listener/dashboard/maintenance DB passwords.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?--target requires a path}"; shift 2 ;;
    --backup-root) BACKUP_ROOT="${2:?--backup-root requires a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

TARGET="$(readlink -m "$TARGET")"
SOURCE_REAL="$(readlink -m "$SOURCE_DIR")"
if [[ "$SOURCE_REAL" == "$TARGET" ]]; then
  echo "Refusing in-place upgrade from the operational source tree." >&2
  echo "Extract the new package elsewhere, then run its upgrade-existing.sh --target $TARGET" >&2
  exit 1
fi
if [[ ! -d "$TARGET" || ! -f "$TARGET/db-config.json" || ! -f "$TARGET/listener.py" ]]; then
  echo "No existing mini-SIEM installation found at $TARGET." >&2
  echo "Use fresh-install.sh for a new installation." >&2
  exit 1
fi

operational=0
for marker in \
  "$TARGET/siem.db" \
  "$TARGET/db-listener-credentials.json" \
  "$TARGET/db-dashboard-credentials.json" \
  "$TARGET/db-maintenance-credentials.json" \
  /etc/systemd/system/mini-siem-listener.service \
  /etc/systemd/system/mini-siem-dashboard.service; do
  [[ -e "$marker" ]] && operational=1
done
if [[ "$operational" != 1 ]]; then
  echo "Target does not contain operational mini-SIEM state." >&2
  echo "Upgrade refuses to guess; use fresh-install.sh for a new installation." >&2
  exit 1
fi

PARENT="$(dirname "$TARGET")"
BASE="$(basename "$TARGET")"
STAGE="$PARENT/.${BASE}.stage-$TIMESTAMP"
PREVIOUS="$PARENT/${BASE}.previous-$TIMESTAMP"
FAILED="$PARENT/${BASE}.failed-$TIMESTAMP"
EVIDENCE_DIR="$BACKUP_ROOT/$TIMESTAMP"
mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

BACKEND="$(python3 - "$TARGET/db-config.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    print((json.load(fh).get('backend') or 'sqlite').strip().lower())
PY
)"

if [[ "$BACKEND" != "postgres" && "$BACKEND" != "sqlite" ]]; then
  echo "Unsupported existing database backend: $BACKEND" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE"
(
  cd "$SOURCE_REAL"
  tar --exclude='./.git' --exclude='./__pycache__' --exclude='./.pytest_cache' \
      --exclude='./.venv' --exclude='./venv' --exclude='*.pyc' --exclude='*.pyo' \
      -cf - .
) | (cd "$STAGE" && tar -xf -)

# Source-level preflight before touching the running installation.
python3 -m compileall -q "$STAGE"
find "$STAGE" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$STAGE" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
for script in "$STAGE"/*.sh; do
  [[ -f "$script" ]] && bash -n "$script"
done

SERVICES=(mini-siem-listener mini-siem-dashboard mini-siem-event-partitions.timer mini-siem-event-partitions.service)
WERE_ACTIVE=()
if command -v systemctl >/dev/null 2>&1; then
  for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      WERE_ACTIVE+=("$svc")
    fi
  done
  systemctl stop mini-siem-event-partitions.timer 2>/dev/null || true
  systemctl stop mini-siem-event-partitions.service 2>/dev/null || true
  systemctl stop mini-siem-dashboard 2>/dev/null || true
  systemctl stop mini-siem-listener 2>/dev/null || true
fi

rollback_tree() {
  local rc=$?
  trap - ERR
  echo "Upgrade FAILED at stage: ${CURRENT_STAGE}" >&2
  python3 - "$EVIDENCE_DIR/upgrade-failure.json" "$CURRENT_STAGE" "$rc" "${RESOLVED_OWNER:-}" "${PG_DUMP_METHOD:-}" "${PG_DUMP_CLIENT_VERSION:-}" "${PG_SERVER_VERSION:-}" <<'PYFAIL' || true
import json, os, sys, datetime
out, stage, rc, owner, dump_method, dump_client, server_version = sys.argv[1:]
payload = {
    "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "stage": stage,
    "exit_code": int(rc),
    "resolved_owner": owner,
    "pg_dump_method": dump_method,
    "pg_dump_client_version": dump_client,
    "postgres_server_version": server_version,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
os.chmod(out, 0o600)
PYFAIL
  echo "Upgrade failed; restoring previous application tree..." >&2
  if [[ -d "$PREVIOUS" ]]; then
    if [[ -d "$TARGET" ]]; then
      rm -rf "$FAILED"
      mv "$TARGET" "$FAILED" || true
    fi
    mv "$PREVIOUS" "$TARGET" || true
  fi
  if [[ -x "$TARGET/install-services.sh" ]]; then
    (cd "$TARGET" && ./install-services.sh) || true
  fi
  echo "Rollback tree restored. Database backup/evidence: $EVIDENCE_DIR" >&2
  exit "$rc"
}
trap rollback_tree ERR

# Copy persistent runtime state only after services are stopped. The old target
# remains untouched until the final directory cutover and therefore is itself
# the immediate rollback copy.
for f in db-config.json auth-config.json \
         db-listener-credentials.json db-dashboard-credentials.json db-maintenance-credentials.json \
         siem.db siem.db-wal siem.db-shm; do
  if [[ -e "$TARGET/$f" ]]; then
    rm -rf "$STAGE/$f"
    cp -a "$TARGET/$f" "$STAGE/$f"
  fi
done
for d in archive backups .venv venv; do
  if [[ -e "$TARGET/$d" ]]; then
    rm -rf "$STAGE/$d"
    cp -a "$TARGET/$d" "$STAGE/$d"
  fi
done

# Preserve a small non-secret upgrade inventory outside the app tree.
python3 - "$TARGET/db-config.json" "$EVIDENCE_DIR/pre-upgrade-state.json" <<'PY'
import json, os, sys, datetime
src, out = sys.argv[1:]
with open(src, encoding='utf-8') as fh:
    cfg=json.load(fh)
pg=cfg.get('postgres') or {}
payload={
  'captured_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'backend': cfg.get('backend','sqlite'),
  'postgres': {k: pg.get(k) for k in ('host','port','dbname','connect_timeout')},
  'postgres_privilege_boundary': cfg.get('postgres_privilege_boundary') or {},
}
with open(out,'w',encoding='utf-8') as fh:
    json.dump(payload,fh,indent=2,sort_keys=True)
os.chmod(out,0o600)
PY

if [[ "$BACKEND" == "postgres" ]]; then
  for f in db-listener-credentials.json db-dashboard-credentials.json db-maintenance-credentials.json; do
    [[ -f "$STAGE/$f" ]] || { echo "Existing split-role credential missing: $TARGET/$f" >&2; false; }
  done
  if ! command -v pg_dump >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    echo "PostgreSQL upgrade backup requires a compatible host pg_dump or a local Docker PostgreSQL container." >&2
    false
  fi

  readarray -t PGINFO < <(python3 - "$STAGE/db-config.json" <<'PY'
import json, os, sys
with open(sys.argv[1], encoding='utf-8') as fh: c=json.load(fh)
p=c.get('postgres') or {}; b=c.get('postgres_privilege_boundary') or {}
print(p.get('host') or 'localhost')
print(int(p.get('port') or 5432))
print(p.get('dbname') or 'minisiem')
print(os.environ.get('MINISIEM_PG_OWNER_USER') or b.get('owner_role') or '')
print('1' if b.get('enabled') else '0')
PY
)
  PGHOST="${PGINFO[0]}"; PGPORT="${PGINFO[1]}"; PGDB="${PGINFO[2]}"; OWNER_USER="${PGINFO[3]}"; BOUNDARY="${PGINFO[4]}"

  if [[ "$BOUNDARY" != 1 ]]; then
    echo "upgrade-existing currently supports split-role PostgreSQL deployments only." >&2
    echo "Legacy shared owner/runtime deployments require the controlled legacy-role migration path." >&2
    false
  fi

  TARGET_PYTHON=""
  for p in "$TARGET/.venv/bin/python3" "$TARGET/.venv/bin/python" "$TARGET/venv/bin/python3" "$TARGET/venv/bin/python"; do
    [[ -x "$p" ]] && { TARGET_PYTHON="$p"; break; }
  done
  [[ -n "$TARGET_PYTHON" ]] || { echo "Existing installation has no usable project Python runtime." >&2; false; }

  set_stage "postgres-owner-discovery"
  if [[ -z "$OWNER_USER" ]]; then
    echo "Discovering existing PostgreSQL database owner using the installed dashboard runtime credential..."
    OWNER_USER="$(
      cd "$TARGET"
      PYTHONPATH="$TARGET" "$TARGET_PYTHON" - "$TARGET/db-config.json" "$TARGET/db-dashboard-credentials.json" "$PGDB" <<'PY'
import sys
import db
config_path, credentials_path, dbname = sys.argv[1:]
cfg = db.load_config(config_path, credentials_path=credentials_path)
conn = db.connect(cfg)
try:
    row = conn.execute(
        "SELECT pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname=?",
        (dbname,),
    ).fetchone()
    if not row:
        raise SystemExit("database owner query returned no row")
    owner = row["owner"] if hasattr(row, "keys") else row[0]
    print(owner or "")
finally:
    conn.close()
PY
    )"
    [[ -n "$OWNER_USER" ]] || { echo "Unable to discover PostgreSQL migration owner." >&2; false; }
  fi
  RESOLVED_OWNER="$OWNER_USER"
  echo "Resolved PostgreSQL migration owner: $OWNER_USER"

  if [[ -z "${MINISIEM_PG_OWNER_PASSWORD:-}" ]]; then
    if [[ ! -t 0 ]]; then
      echo "Set MINISIEM_PG_OWNER_PASSWORD for noninteractive PostgreSQL upgrade." >&2
      false
    fi
    read -rsp "PostgreSQL password for schema owner '$OWNER_USER': " MINISIEM_PG_OWNER_PASSWORD
    echo
    export MINISIEM_PG_OWNER_PASSWORD
  fi
  export MINISIEM_PG_OWNER_USER="$OWNER_USER"

  PG_SERVER_VERSION="$(
    cd "$TARGET"
    PYTHONPATH="$TARGET" "$TARGET_PYTHON" - "$TARGET/db-config.json" "$TARGET/db-dashboard-credentials.json" <<'PY'
import sys
import db
cfg = db.load_config(sys.argv[1], credentials_path=sys.argv[2])
conn = db.connect(cfg)
try:
    row = conn.execute("SHOW server_version").fetchone()
    print((row["server_version"] if hasattr(row, "keys") else row[0]) or "")
finally:
    conn.close()
PY
  )"
  SERVER_MAJOR="${PG_SERVER_VERSION%%.*}"
  [[ "$SERVER_MAJOR" =~ ^[0-9]+$ ]] || { echo "Unable to determine PostgreSQL server major version: $PG_SERVER_VERSION" >&2; false; }
  echo "PostgreSQL server version: $PG_SERVER_VERSION"

  set_stage "postgres-backup"
  DUMP_FILE="$EVIDENCE_DIR/postgres-pre-upgrade.dump"
  DUMP_STDERR="$EVIDENCE_DIR/postgres-pg-dump.stderr"
  : > "$DUMP_STDERR"
  chmod 600 "$DUMP_STDERR"

  LOCAL_PG_DUMP="$(command -v pg_dump || true)"
  LOCAL_MAJOR=""
  if [[ -n "$LOCAL_PG_DUMP" ]]; then
    PG_DUMP_CLIENT_VERSION="$($LOCAL_PG_DUMP --version 2>/dev/null || true)"
    LOCAL_MAJOR="$(printf '%s\n' "$PG_DUMP_CLIENT_VERSION" | sed -nE 's/.* ([0-9]+)(\.[0-9]+)?.*/\1/p' | tail -n1)"
  fi

  if [[ "$LOCAL_MAJOR" =~ ^[0-9]+$ ]] && (( LOCAL_MAJOR >= SERVER_MAJOR )); then
    PG_DUMP_METHOD="host:$LOCAL_PG_DUMP"
    echo "Creating PostgreSQL pre-upgrade dump with compatible host pg_dump ($PG_DUMP_CLIENT_VERSION)..."
    if ! PGPASSWORD="$MINISIEM_PG_OWNER_PASSWORD" "$LOCAL_PG_DUMP" \
      -h "$PGHOST" -p "$PGPORT" -U "$OWNER_USER" -d "$PGDB" \
      -Fc -f "$DUMP_FILE" 2> >(tee "$DUMP_STDERR" >&2); then
      false
    fi
  else
    DOCKER_CONTAINER=""
    if command -v docker >/dev/null 2>&1 && [[ "$PGHOST" == "localhost" || "$PGHOST" == "127.0.0.1" ]]; then
      while IFS=$'\t' read -r cid ports; do
        if printf '%s' "$ports" | grep -Eq "(^|[, ])(127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::\\]):${PGPORT}->5432/tcp"; then
          DOCKER_CONTAINER="$cid"
          break
        fi
      done < <(docker ps --format '{{.ID}}\t{{.Ports}}' 2>/dev/null || true)
    fi

    if [[ -n "$DOCKER_CONTAINER" ]]; then
      CONTAINER_PG_DUMP_VERSION="$(docker exec "$DOCKER_CONTAINER" pg_dump --version 2>/dev/null || true)"
      CONTAINER_MAJOR="$(printf '%s\n' "$CONTAINER_PG_DUMP_VERSION" | sed -nE 's/.* ([0-9]+)(\.[0-9]+)?.*/\1/p' | tail -n1)"
      if [[ "$CONTAINER_MAJOR" =~ ^[0-9]+$ ]] && (( CONTAINER_MAJOR >= SERVER_MAJOR )); then
        PG_DUMP_METHOD="docker:$DOCKER_CONTAINER"
        PG_DUMP_CLIENT_VERSION="$CONTAINER_PG_DUMP_VERSION"
        echo "Host pg_dump is not server-compatible; using PostgreSQL container pg_dump ($CONTAINER_PG_DUMP_VERSION)..."
        export PGPASSWORD="$MINISIEM_PG_OWNER_PASSWORD"
        if ! docker exec -e PGPASSWORD "$DOCKER_CONTAINER" \
          pg_dump -U "$OWNER_USER" -d "$PGDB" -Fc \
          > "$DUMP_FILE" 2> >(tee "$DUMP_STDERR" >&2); then
          unset PGPASSWORD || true
          false
        fi
        unset PGPASSWORD || true
      fi
    fi
  fi

  if [[ -z "$PG_DUMP_METHOD" ]]; then
    echo "No PostgreSQL pg_dump client compatible with server major $SERVER_MAJOR was found." >&2
    echo "Host client: ${PG_DUMP_CLIENT_VERSION:-not found}" >&2
    echo "Install PostgreSQL $SERVER_MAJOR client tools or expose the matching local PostgreSQL Docker container." >&2
    false
  fi
  [[ -s "$DUMP_FILE" ]] || { echo "PostgreSQL backup is empty: $DUMP_FILE" >&2; false; }
  chmod 600 "$DUMP_FILE"

  set_stage "postgres-backup-verify"
  if [[ "$PG_DUMP_METHOD" == host:* ]]; then
    PG_RESTORE_BIN="$(dirname "$LOCAL_PG_DUMP")/pg_restore"
    [[ -x "$PG_RESTORE_BIN" ]] || { echo "Matching pg_restore not found beside $LOCAL_PG_DUMP" >&2; false; }
    "$PG_RESTORE_BIN" -l "$DUMP_FILE" >/dev/null 2>>"$DUMP_STDERR"
  elif [[ "$PG_DUMP_METHOD" == docker:* ]]; then
    docker exec -i "$DOCKER_CONTAINER" pg_restore -l < "$DUMP_FILE" >/dev/null 2>>"$DUMP_STDERR"
  else
    echo "Unknown pg_dump verification method: $PG_DUMP_METHOD" >&2
    false
  fi
  echo "PostgreSQL pre-upgrade dump created and verified: $(du -h "$DUMP_FILE" | awk '{print $1}') via $PG_DUMP_METHOD"

  PYTHON_BIN=""
  for p in "$STAGE/.venv/bin/python3" "$STAGE/.venv/bin/python" "$STAGE/venv/bin/python3" "$STAGE/venv/bin/python"; do
    [[ -x "$p" ]] && { PYTHON_BIN="$p"; break; }
  done
  if [[ -z "$PYTHON_BIN" ]]; then
    python3 -m venv "$STAGE/.venv"
    PYTHON_BIN="$STAGE/.venv/bin/python3"
    "$PYTHON_BIN" -m pip install -r "$STAGE/requirements.txt"
    "$PYTHON_BIN" -m pip install 'psycopg2-binary>=2.9'
  elif ! "$PYTHON_BIN" -c 'import psycopg2' >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install 'psycopg2-binary>=2.9'
  fi

  set_stage "postgres-migration"
  echo "Applying existing-deployment PostgreSQL upgrade without rotating runtime credentials..."
  "$PYTHON_BIN" "$STAGE/tools/postgres_upgrade_existing.py" \
    --db-config "$STAGE/db-config.json" \
    --owner-user "$OWNER_USER" --qualify \
    > "$EVIDENCE_DIR/postgres-upgrade-report.json"
  chmod 600 "$EVIDENCE_DIR/postgres-upgrade-report.json"
else
  # SQLite rollback is the stopped old target itself. Keep an additional DB
  # copy outside the app tree for operator recovery.
  if [[ -f "$TARGET/siem.db" ]]; then
    cp -a "$TARGET/siem.db" "$EVIDENCE_DIR/siem-pre-upgrade.db"
    chmod 600 "$EVIDENCE_DIR/siem-pre-upgrade.db" || true
  fi
fi

# Stable-path cutover. The old source tree remains intact as PREVIOUS.
if [[ -e "$PREVIOUS" ]]; then
  echo "Backup target already exists: $PREVIOUS" >&2
  false
fi
mv "$TARGET" "$PREVIOUS"
mv "$STAGE" "$TARGET"

# Low-level deterministic unit/permission reconciliation. No fresh DB bootstrap.
export MINISIEM_INSTALL_ENTRYPOINT=upgrade
set_stage "service-install"
(cd "$TARGET" && ./install-services.sh)

if [[ "$BACKEND" == "postgres" ]]; then
  PYTHON_BIN=""
  for p in "$TARGET/.venv/bin/python3" "$TARGET/.venv/bin/python" "$TARGET/venv/bin/python3" "$TARGET/venv/bin/python"; do
    [[ -x "$p" ]] && { PYTHON_BIN="$p"; break; }
  done
  [[ -n "$PYTHON_BIN" ]] || { echo "No project Python after cutover" >&2; false; }
  set_stage "post-upgrade-privilege-check"
  "$PYTHON_BIN" "$TARGET/tools/postgres_privilege_check.py" --db-config "$TARGET/db-config.json" \
    > "$EVIDENCE_DIR/post-upgrade-privilege-check.txt"
fi

set_stage "service-health"
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet mini-siem-listener
  systemctl is-active --quiet mini-siem-dashboard
fi

trap - ERR
unset MINISIEM_PG_OWNER_PASSWORD PGPASSWORD || true

echo "Upgrade completed successfully."
echo "Previous application tree: $PREVIOUS"
echo "Upgrade/backup evidence: $EVIDENCE_DIR"
echo "Keep both until post-upgrade acceptance is complete."
