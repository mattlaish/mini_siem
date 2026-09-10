# Migration Completion Verification & Cutover Phase

## Objective

Finalize PostgreSQL migration with verification evidence and controlled cutover.

## Added

- final migration evidence report
- source/target comparison checkpoint
- checksum verification checkpoint
- admin identity validation checkpoint
- service health validation checkpoint
- cutover decision boundary
- rollback decision tracking

## Safety

Cutover is not automatic.

Required before activation:

- migration transaction completed
- row counts verified
- checksums compared
- admin login preserved
- services validated
- rollback path confirmed

## Final evidence archive

Required artifacts:

- transaction report
- per-table import report
- duplicate handling report
- verification report
- cutover decision record

## Completion state

Migration is considered complete only after successful verification and controlled service switch-over.
