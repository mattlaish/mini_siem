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
#   3. Rotate: keep the newest $KEEP backup copies
#      (this NEVER rotates/deletes sealed evidence archive segments)
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
CHECKPOINT_WAL_MB="${CHECKPOINT_WAL_MB:-256}"
INCREMENTAL_VACUUM_PAGES="${INCREMENTAL_VACUUM_PAGES:-2000}"

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

# ---- 4. bounded online housekeeping -------------------------------------
# Never run a full VACUUM against the live SIEM. Passive checkpoint only when
# WAL has grown beyond the threshold; incremental_vacuum only when the DB was
# created with auto_vacuum=INCREMENTAL.
wal="$DB-wal"
wal_bytes=0
[ -f "$wal" ] && wal_bytes=$(stat -c%s "$wal" 2>/dev/null || echo 0)
threshold_bytes=$((CHECKPOINT_WAL_MB * 1024 * 1024))
if [ "$wal_bytes" -ge "$threshold_bytes" ]; then
    log "WAL ${wal_bytes} bytes >= ${threshold_bytes}; requesting PASSIVE checkpoint"
    sqlite3 "$DB" 'PRAGMA wal_checkpoint(PASSIVE);' || log "PASSIVE checkpoint busy/failed; will retry next run"
fi
auto_vacuum=$(sqlite3 "$DB" 'PRAGMA auto_vacuum;' 2>/dev/null || echo 0)
page_count=$(sqlite3 "$DB" 'PRAGMA page_count;' 2>/dev/null || echo '?')
freelist=$(sqlite3 "$DB" 'PRAGMA freelist_count;' 2>/dev/null || echo '?')
log "pages=$page_count freelist=$freelist auto_vacuum=$auto_vacuum"
if [ "$auto_vacuum" = "2" ] && [ "$INCREMENTAL_VACUUM_PAGES" -gt 0 ]; then
    log "requesting incremental_vacuum($INCREMENTAL_VACUUM_PAGES)"
    sqlite3 "$DB" "PRAGMA incremental_vacuum($INCREMENTAL_VACUUM_PAGES);" || log "incremental vacuum skipped/busy"
fi
sqlite3 "$DB" 'PRAGMA optimize;' >/dev/null 2>&1 || true

log "done — $count backup(s) retained (keeping newest $KEEP)"
exit 0
