#!/usr/bin/env bash
#
# mini-SIEM database maintenance
# ==============================
# WAL-safe online backup + rotation + integrity verification for siem.db.
# Designed to run from cron. Does NOT need the dashboard running, and is
# safe to run while the SIEM is live (uses SQLite's online .backup, never
# a raw cp of a WAL database).
#
# What it does each run:
#   1. Online-backup siem.db -> backups/siem-YYYYMMDD-HHMMSS.db
#   2. Run PRAGMA integrity_check on the BACKUP (checking the copy avoids
#      contending with the live writer)
#   3. Rotate: keep the newest $KEEP backups
#   4. If integrity fails, shout: stderr + logger + optional syslog to the
#      SIEM itself + optional email
#
# Usage:
#   ./db-maintenance.sh                      # uses defaults below
#   DB=/path/siem.db BACKUP_DIR=/mnt/backups ./db-maintenance.sh
#
# Cron (daily 03:00):
#   0 3 * * * /home/matt/siem123/mini_siem/db-maintenance.sh >> /home/matt/siem-maint.log 2>&1
#
# Exit codes: 0 = ok, 1 = integrity failed, 2 = backup/setup error.

set -u

# ---- config (override via environment) -----------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="${DB:-$SCRIPT_DIR/siem.db}"
BACKUP_DIR="${BACKUP_DIR:-$SCRIPT_DIR/backups}"
KEEP="${KEEP:-14}"                 # how many backups to retain
ALERT_EMAIL="${ALERT_EMAIL:-}"     # optional: email address for failures
SIEM_SYSLOG="${SIEM_SYSLOG:-}"     # optional: host:port to send a failure syslog to (e.g. 127.0.0.1:514)

stamp="$(date -u +%Y%m%d-%H%M%S)"
dest="$BACKUP_DIR/siem-$stamp.db"

log()   { echo "[$(date -u +%H:%M:%S)] $*"; }
alert() {
    local msg="mini-SIEM DB maintenance: $*"
    echo "$msg" >&2
    command -v logger >/dev/null 2>&1 && logger -t siem-dbcheck "$msg"
    [ -n "$ALERT_EMAIL" ] && command -v mail >/dev/null 2>&1 && \
        echo "$msg" | mail -s "mini-SIEM DB ALERT" "$ALERT_EMAIL"
    if [ -n "$SIEM_SYSLOG" ]; then
        host="${SIEM_SYSLOG%%:*}"; port="${SIEM_SYSLOG##*:}"
        # PRI 27 = user.err ; RFC3164-ish line (bash /dev/udp; ignored if unsupported)
        ( printf '<27>%s db-maintenance: %s' "$(date '+%b %e %H:%M:%S')" "$msg" \
            > "/dev/udp/$host/$port" ) 2>/dev/null || true
    fi
}

command -v sqlite3 >/dev/null 2>&1 || { alert "sqlite3 not installed"; exit 2; }
[ -f "$DB" ] || { alert "database not found at $DB"; exit 2; }
mkdir -p "$BACKUP_DIR" || { alert "cannot create backup dir $BACKUP_DIR"; exit 2; }

# ---- 1. online backup (WAL-safe) -----------------------------------------
log "backing up $DB -> $dest"
if ! sqlite3 "$DB" ".backup '$dest'"; then
    alert "BACKUP FAILED for $DB (source may be corrupt or locked)"
    exit 2
fi
size=$(stat -c%s "$dest" 2>/dev/null || echo "?")
log "backup written (${size} bytes)"

# ---- 2. integrity check on the backup copy -------------------------------
log "verifying backup integrity"
result="$(sqlite3 "$dest" 'PRAGMA integrity_check;' 2>&1)"
if [ "$result" = "ok" ]; then
    log "integrity: ok"
else
    alert "INTEGRITY CHECK FAILED on backup of $DB -> $result"
    # keep the bad-source evidence; don't rotate it away
    exit 1
fi

# ---- 3. rotate: keep newest $KEEP ----------------------------------------
mapfile -t backups < <(ls -1 "$BACKUP_DIR"/siem-*.db 2>/dev/null | sort)
count=${#backups[@]}
if [ "$count" -gt "$KEEP" ]; then
    remove=$((count - KEEP))
    for ((i=0; i<remove; i++)); do
        rm -f "${backups[$i]}" && log "rotated out $(basename "${backups[$i]}")"
    done
fi

log "done — $count backup(s) retained (keeping newest $KEEP)"
exit 0
