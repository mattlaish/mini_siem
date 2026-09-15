# mini-SIEM Testing Handover

## Completed Validation Areas

### PostgreSQL Upgrade Path

Required validation:

- existing PostgreSQL schema startup
- schema_migrations handling
- fresh database initialization
- migration skip behavior
- ALTER safety

Status:
Implemented path exists. Full regression evidence must be collected in next session.

---

## CEF Parser Validation Required

Test cases:

1. Standard CEF event
2. CEF with src/dst/suser/act/dpt
3. Vendor custom fields
4. Malformed CEF
5. Empty extension section
6. Unknown CEF vendor format

Expected behavior:

- Parsed fields displayed when possible
- Raw event always preserved on failure

---

## Operational Testing Required

- service restart after upgrade
- reboot/start-order test
- PostgreSQL unavailable behavior
- listener failure behavior
- debug evidence collection


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Phase 12.3 Backup Restore Tests

- backup manifest validation
- checksum validation
- restore preflight validation
- secret exclusion verification

Live PostgreSQL restore drill remains DEFERRED.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED
