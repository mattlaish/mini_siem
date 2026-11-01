#!/usr/bin/env bash
# Fresh-install entry point for mini-SIEM.
#
# This script is intentionally NOT an upgrade path. It refuses an existing
# operational installation and delegates low-level service/unit creation to
# install-services.sh only after fresh-install preflight succeeds.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/opt/mini_siem"

usage() {
  cat <<EOF
Usage: sudo $0 [--target /opt/mini_siem] [--resume]

Fresh installation only.
PostgreSQL fresh bootstrap additionally requires:
  MINISIEM_PG_BOOTSTRAP_USER=<customer-admin>
Optional noninteractive password:
  MINISIEM_PG_BOOTSTRAP_PASSWORD=...

--resume resumes only the same checkpointed interrupted fresh installation.
It never adopts an operational installation and never acts as an upgrade path.

Do not use this script for an existing operational installation. Use upgrade-existing.sh.
EOF
}

RESUME=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?--target requires a path}"; shift 2 ;;
    --resume) RESUME=1; shift ;;
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
STATE_PATH="${TARGET}/.fresh-install-state.json"
RESUME_SECRET_PATH="${TARGET}/.fresh-install-resume-secrets.json"

existing_service=0
for unit in /etc/systemd/system/mini-siem-listener.service /etc/systemd/system/mini-siem-dashboard.service; do
  [[ -e "$unit" ]] && existing_service=1
done
if [[ "$existing_service" == 1 && "$RESUME" != 1 ]]; then
  echo "Existing mini-SIEM systemd units detected. Fresh install refuses to adopt an operational installation." >&2
  echo "Use upgrade-existing.sh instead." >&2
  exit 1
fi
if [[ "$RESUME" == 1 && "$existing_service" == 1 ]]; then
  if systemctl is-active --quiet mini-siem-listener.service 2>/dev/null \
     && systemctl is-active --quiet mini-siem-dashboard.service 2>/dev/null; then
    echo "mini-SIEM services are already active; this installation appears operational." >&2
    echo "--resume is only for interrupted fresh installs. Use upgrade-existing.sh." >&2
    exit 1
  fi
fi

if [[ -f "$STATE_PATH" && "$RESUME" != 1 ]]; then
  echo "Interrupted fresh-install checkpoint detected: $STATE_PATH" >&2
  echo "Use: sudo $0 --target '$TARGET' --resume" >&2
  exit 1
fi
if [[ "$RESUME" == 1 && ! -f "$STATE_PATH" ]]; then
  echo "No fresh-install checkpoint exists at $STATE_PATH; refusing --resume." >&2
  echo "Use normal fresh install for an empty target or upgrade-existing.sh for an operational installation." >&2
  exit 1
fi

# A source tree may already live at TARGET. Only runtime/credential state is an
# operational marker; source files alone are not.
if [[ -d "$TARGET" ]]; then
  for marker in siem.db db-listener-credentials.json db-dashboard-credentials.json db-maintenance-credentials.json; do
    if [[ -e "$TARGET/$marker" && "$RESUME" != 1 ]]; then
      echo "Existing runtime state detected at $TARGET/$marker." >&2
      echo "Fresh install refuses to overwrite it; use upgrade-existing.sh." >&2
      exit 1
    fi
  done
fi

if [[ "$RESUME" == 1 && ! -d "$TARGET" ]]; then
  echo "Interrupted target directory is missing: $TARGET" >&2
  exit 1
fi

if [[ "$SOURCE_REAL" != "$TARGET" && "$RESUME" != 1 ]]; then
  if [[ -e "$TARGET" ]] && [[ -n "$(find "$TARGET" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    echo "Target exists and is not empty: $TARGET" >&2
    echo "Fresh install requires an empty/nonexistent target." >&2
    exit 1
  fi
  mkdir -p "$TARGET"
  # Copy the complete modifiable source, but never copy local caches/venvs from
  # an operator staging directory.
  (
    cd "$SOURCE_REAL"
    tar --exclude='./.git' --exclude='./__pycache__' --exclude='./.pytest_cache' \
        --exclude='./.venv' --exclude='./venv' --exclude='*.pyc' --exclude='*.pyo' \
        --exclude='./db-config.json' \
        -cf - .
  ) | (cd "$TARGET" && tar -xf -)
fi

# Database selection is an explicit operator step performed before fresh install.
# The source artifact never carries runtime db-config.json; configure-db.py creates
# deployment intent in the extracted source tree, and fresh-install.sh must consume
# exactly that intent without deleting, replacing, or silently defaulting it.
SOURCE_CONFIG="$SOURCE_REAL/db-config.json"
TARGET_CONFIG="$TARGET/db-config.json"

if [[ ! -f "$SOURCE_CONFIG" ]]; then
  echo "Database configuration is missing: $SOURCE_CONFIG" >&2
  echo "Run: python3 configure-db.py" >&2
  echo "Then rerun fresh-install.sh." >&2
  exit 1
fi

BACKEND="$(python3 - "$SOURCE_CONFIG" <<'PY'
import json, sys
path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
except Exception as exc:
    raise SystemExit(f"Invalid database configuration {path}: {exc}")
backend = cfg.get("backend")
if not isinstance(backend, str) or backend.strip().lower() not in {"sqlite", "postgres"}:
    raise SystemExit("db-config.json must explicitly set backend to 'sqlite' or 'postgres'")
backend = backend.strip().lower()
if backend == "postgres":
    pg = cfg.get("postgres") or {}
    missing = [k for k in ("host", "port", "dbname") if not pg.get(k)]
    if missing:
        raise SystemExit("PostgreSQL db-config.json missing: " + ", ".join(missing))
    if pg.get("user") or pg.get("password"):
        raise SystemExit("PostgreSQL db-config.json must not persist bootstrap/owner/runtime credentials")
print(backend)
PY
)"

# When installing from a staging directory, copy the validated non-secret
# deployment intent after the source tree has been copied. The general source
# copy intentionally excludes runtime db-config.json so artifacts stay clean.
if [[ "$SOURCE_REAL" != "$TARGET" && "$RESUME" != 1 ]]; then
  install -m 0640 "$SOURCE_CONFIG" "$TARGET_CONFIG"
elif [[ "$SOURCE_REAL" != "$TARGET" && "$RESUME" == 1 ]]; then
  if ! cmp -s "$SOURCE_CONFIG" "$TARGET_CONFIG"; then
    echo "Source db-config.json differs from the interrupted target configuration; refusing --resume." >&2
    exit 1
  fi
fi

# Re-read the target copy strictly. A copy/corruption mismatch must stop the
# install rather than change database engines.
TARGET_BACKEND="$(python3 - "$TARGET_CONFIG" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    cfg = json.load(fh)
backend = cfg.get("backend")
if backend not in ("sqlite", "postgres"):
    raise SystemExit("target db-config.json has unsupported/missing backend")
print(backend)
PY
)"
if [[ "$TARGET_BACKEND" != "$BACKEND" ]]; then
  echo "Database backend changed while staging: source=$BACKEND target=$TARGET_BACKEND" >&2
  exit 1
fi

STATE_TOOL="$TARGET/tools/fresh_install_state.py"
if [[ ! -f "$STATE_TOOL" ]]; then
  echo "Fresh-install state helper is missing: $STATE_TOOL" >&2
  exit 1
fi
if [[ "$RESUME" == 1 ]]; then
  python3 "$STATE_TOOL" validate-resume --state "$STATE_PATH" --target "$TARGET" \
    --source "$SOURCE_REAL" --backend "$BACKEND" --config "$TARGET_CONFIG" >/dev/null
else
  python3 "$STATE_TOOL" init --state "$STATE_PATH" --target "$TARGET" \
    --source "$SOURCE_REAL" --backend "$BACKEND" --config "$TARGET_CONFIG" >/dev/null
fi
export MINISIEM_FRESH_STATE_PATH="$STATE_PATH"
export MINISIEM_FRESH_RESUME_SECRET_PATH="$RESUME_SECRET_PATH"
export MINISIEM_INSTALL_RESUME="$RESUME"

# Generate all non-bootstrap PostgreSQL fresh-install secrets before any
# database mutation. The root-only file is reused unchanged by --resume and
# removed only after post-install verification reaches OPERATIONAL.
if [[ "$BACKEND" == "postgres" ]]; then
  PYTHONPATH="$TARGET" python3 - "$RESUME_SECRET_PATH" "$RESUME" <<'PY'
from pathlib import Path
import sys
from tools.postgres_bootstrap import _resume_secret_payload
_resume_secret_payload(Path(sys.argv[1]), resume=(sys.argv[2] == "1"))
PY
fi

mark_interrupted() {
  python3 "$STATE_TOOL" interrupt --state "$STATE_PATH" >/dev/null 2>&1 || true
}

case "$BACKEND" in
  postgres)
    if [[ -z "${MINISIEM_PG_BOOTSTRAP_USER:-}" ]]; then
      read -r -p "PostgreSQL bootstrap/admin user [postgres]: " MINISIEM_PG_BOOTSTRAP_USER
      MINISIEM_PG_BOOTSTRAP_USER="${MINISIEM_PG_BOOTSTRAP_USER:-postgres}"
      export MINISIEM_PG_BOOTSTRAP_USER
    fi
    echo "Fresh PostgreSQL install: bootstrap -> owner migration -> split runtime roles -> services"
    export MINISIEM_INSTALL_ENTRYPOINT=fresh
    "$TARGET/install-services.sh" --bootstrap-postgres || { rc=$?; mark_interrupted; exit "$rc"; }
    ;;
  sqlite)
    echo "Fresh SQLite install: initialize local database -> services"
    export MINISIEM_INSTALL_ENTRYPOINT=fresh
    "$TARGET/install-services.sh" || { rc=$?; mark_interrupted; exit "$rc"; }
    ;;
  *)
    echo "Unsupported database backend: $BACKEND" >&2
    exit 1
    ;;
esac
