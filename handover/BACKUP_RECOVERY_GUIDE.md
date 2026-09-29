# Backup Recovery Guide

Status: `IMPLEMENTED_TESTING_DEFERRED`

## PostgreSQL

Use `tools/postgres_backup_restore.py` for controlled backup/recovery evidence.

- Backup: custom-format `pg_dump`, `pg_restore -l` validation, archive mode 0600,
  SHA-256/byte-count manifest, PostgreSQL/server version and migration-ledger metadata.
  Archive/manifest overwrite and aliasing are refused; a dump that fails archive
  validation is removed rather than left as apparently usable recovery evidence.
- Secrets: owner/bootstrap passwords are never written into the manifest.
- Restore: recovery-to-new-database only; an existing database is refused.
- Ownership: target database uses the current deployment schema-owner role; the
  source owner stored in a historical manifest is evidence only. Archive ownership
  and ACLs are not replayed.
- Verification: manifest structure/size/checksum and the exact migration ledger are
  validated before/after restore. Current-schema backups require all runtime tables.
  Older supported ledgers are marked `migration_required`; newer-than-source ledgers
  fail closed.
- Failure: the newly-created incomplete recovery DB can be dropped after failed
  verification.

The pre-upgrade PostgreSQL dump inside `upgrade-existing.sh` remains mandatory and
separate from this operator backup/recovery workflow. Live restore drills, service
cutover, RPO/RTO and historical-backup compatibility remain deferred release gates.

## SQLite

The Web backup and maintenance paths use SQLite online backup rather than raw file
copy. Web-created backups use unique non-overwriting names, mode 0600, full integrity
verification and SHA-256 reporting; retention runs only after the new copy verifies.
An integrity failure is not returned as success. The cron maintenance path uses
private creation defaults, unique same-second names and positive retention validation.
Preserve database/WAL consistency and do not make mutable database state world-writable
as a recovery workaround.
