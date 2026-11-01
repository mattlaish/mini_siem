> **Current executable gate exists.** `release_engineering/release_gate.py` is the
> fail-closed release decision helper. This checklist does not itself authorize a release.

# Release Checklist

Status: `IMPLEMENTED_TESTING_DEFERRED`

The executable release gate checks:

- source completeness and required critical files;
- Python/shell/JavaScript syntax plus placeholder-truth gate;
- clean-extracted artifact safety/parity and embedded per-file manifest hashes;
- canonical documentation synchronization;
- explicit evidence for PostgreSQL, systemd/SELinux, install/upgrade/resume,
  backup/restore, performance, Alert Lifecycle/browser, AI provider, ingest/detection,
  operations/security, and full regression qualification domains;
- artifact/source evidence provenance hashes;
- explicit human release approval after all technical domains pass.

Any missing/non-PASS qualification domain keeps the decision `BLOCKED`. Packaging
success alone never promotes the product to `RELEASED`.
