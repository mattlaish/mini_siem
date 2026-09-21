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
Usage: sudo $0 [--target /opt/mini_siem]

Fresh installation only.
PostgreSQL fresh bootstrap additionally requires:
  MINISIEM_PG_BOOTSTRAP_USER=<customer-admin>
Optional noninteractive password:
  MINISIEM_PG_BOOTSTRAP_PASSWORD=...

Do not use this script for an existing installation. Use upgrade-existing.sh.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?--target requires a path}"; shift 2 ;;
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

existing_service=0
for unit in /etc/systemd/system/mini-siem-listener.service /etc/systemd/system/mini-siem-dashboard.service; do
  [[ -e "$unit" ]] && existing_service=1
done
if [[ "$existing_service" == 1 ]]; then
  echo "Existing mini-SIEM systemd units detected. Fresh install refuses to adopt an operational installation." >&2
  echo "Use upgrade-existing.sh instead." >&2
  exit 1
fi

# A source tree may already live at TARGET. Only runtime/credential state is an
# operational marker; source files alone are not.
if [[ -d "$TARGET" ]]; then
  for marker in siem.db db-listener-credentials.json db-dashboard-credentials.json db-maintenance-credentials.json; do
    if [[ -e "$TARGET/$marker" ]]; then
      echo "Existing runtime state detected at $TARGET/$marker." >&2
      echo "Fresh install refuses to overwrite it; use upgrade-existing.sh." >&2
      exit 1
    fi
  done
fi

if [[ "$SOURCE_REAL" != "$TARGET" ]]; then
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
if [[ "$SOURCE_REAL" != "$TARGET" ]]; then
  install -m 0640 "$SOURCE_CONFIG" "$TARGET_CONFIG"
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

case "$BACKEND" in
  postgres)
    if [[ -z "${MINISIEM_PG_BOOTSTRAP_USER:-}" ]]; then
      read -r -p "PostgreSQL bootstrap/admin user [postgres]: " MINISIEM_PG_BOOTSTRAP_USER
      MINISIEM_PG_BOOTSTRAP_USER="${MINISIEM_PG_BOOTSTRAP_USER:-postgres}"
      export MINISIEM_PG_BOOTSTRAP_USER
    fi
    echo "Fresh PostgreSQL install: bootstrap -> owner migration -> split runtime roles -> services"
    export MINISIEM_INSTALL_ENTRYPOINT=fresh
    exec "$TARGET/install-services.sh" --bootstrap-postgres
    ;;
  sqlite)
    echo "Fresh SQLite install: initialize local database -> services"
    exec "$TARGET/install-services.sh"
    ;;
  *)
    echo "Unsupported database backend: $BACKEND" >&2
    exit 1
    ;;
esac
