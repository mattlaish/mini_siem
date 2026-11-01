# Reclassified Tool Scaffolds

Status: `PLANNED`

The following former `tools/*.py` files were executable-shaped design scaffolds. They did not perform the PostgreSQL migration, validation, cutover, HA, performance, or release actions implied by their names; most emitted static `pending` JSON. They were removed from executable source so their presence cannot be counted as implementation or test evidence.

Real replacements must perform the named checks/actions, produce evidence from observed state, fail closed on missing evidence, and have non-trivial tests.

| Former executable | Classification |
| --- | --- |
| `tools/controlled-postgres-migration-execution.py` | `PLANNED` scaffold — mini-SIEM Controlled PostgreSQL Migration Execution.  Controlled write execution boundary.  |
| `tools/controlled-postgres-write-executor.py` | `PLANNED` scaffold — mini-SIEM Controlled PostgreSQL Write Executor.  Execution boundary for controlled migration.  |
| `tools/controlled-postgres-write-importer.py` | `PLANNED` scaffold — mini-SIEM Controlled PostgreSQL Write Importer foundation.  Safety design: - explicit execution flag |
| `tools/controlled-table-import.py` | `PLANNED` scaffold — mini-SIEM Controlled Table Import Engine.  Phase: - controlled table planning |
| `tools/data-transfer-verifier.py` | `PLANNED` scaffold — mini-SIEM Real Data Transfer Verification stage.  This stage introduces verification workflow: - source snapshot |
| `tools/migration-completion-cutover.py` | `PLANNED` scaffold — mini-SIEM Migration Completion Verification & Cutover.  Final migration verification boundary.  |
| `tools/migration-dry-run-engine.py` | `PLANNED` scaffold — mini-SIEM Migration Dry-Run Engine.  No-write validation mode.  |
| `tools/migration-final-release-check.py` | `PLANNED` scaffold — mini-SIEM Migration Final Release Check.  Final non-destructive release checklist.  |
| `tools/migration-validation-gate.py` | `PLANNED` scaffold — mini-SIEM Migration Validation Gate.  Read-only validation stage.  |
| `tools/post-migration-hardening-recovery.py` | `PLANNED` scaffold — mini-SIEM Post-Migration Hardening & Recovery Validation.  Final post-cutover validation boundary.  |
| `tools/postgres-enterprise-operations-check.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Enterprise Operations Baseline Check.  Enterprise operations validation boundary.  |
| `tools/postgres-ha-reliability-check.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Advanced Reliability & HA Preparation.  Reliability validation boundary.  |
| `tools/postgres-operational-automation-check.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Operational Automation Check.  Operational automation validation boundary.  |
| `tools/postgres-performance-scaling-check.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Performance & Scaling Hardening Check.  Performance validation boundary.  |
| `tools/postgres-production-readiness-check.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Production Ready v1 readiness check.  Operational validation boundary: - PostgreSQL connectivity readiness |
| `tools/postgres-read-validation.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Read Validation and Migration Unlock Gate.  Read-only validation layer: - PostgreSQL schema inspection boundary |
| `tools/postgres-runtime-hardening-check.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Runtime Hardening Check.  Operational runtime validation boundary.  |
| `tools/production-migration-finalization.py` | `PLANNED` scaffold — mini-SIEM Production Migration Finalization.  Finalization checklist boundary.  |
| `tools/real-migration-transaction-execution.py` | `PLANNED` scaffold — mini-SIEM Real Migration Transaction Execution.  Controlled transaction execution framework.  |
| `tools/real-postgres-writer-activation.py` | `PLANNED` scaffold — mini-SIEM Real PostgreSQL Writer Activation.  Controlled activation layer for PostgreSQL writers.  |
| `tools/table-writer-engine.py` | `PLANNED` scaffold — mini-SIEM Table Writer Engine foundation.  Implements controlled writer workflow: - table allow-list |
| `tools/transactional-import-verification.py` | `PLANNED` scaffold — mini-SIEM Transactional Import + Verification foundation.  Planning only. No PostgreSQL writes. |
| `tools/validated-postgres-table-writer.py` | `PLANNED` scaffold — mini-SIEM Validated PostgreSQL Table Writer.  Migration execution framework.  |
| `tools/controlled-import-engine.py` | `PLANNED` scaffold — mini-SIEM Controlled Import Engine foundation. Safety properties: - dry-run by default - no destructive operations - no automatic user replacement - no administrator recreation - produces migration plan/report |
| `tools/individual-postgres-writers.py` | `PLANNED` scaffold — mini-SIEM Individual PostgreSQL Writers foundation. Adds: - explicit column mappings - parameterized INSERT generation - cursor lifecycle model - duplicate detection strategy - transaction integration model - per-table verification evidence No production PostgreSQL write is executed by this framewor |
| `tools/migrate-sqlite-to-postgres.py` | `PLANNED` scaffold — SQLite -> PostgreSQL data migration foundation for mini-SIEM. Safety goals: - Never delete PostgreSQL data. - Never overwrite existing users. - Migration is explicit, not automatic. - Schema initialization and data migration are separate operations. Current mode: - Inventory / plan only. - No Postgr |
| `tools/postgres-data-transfer-executor.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Data Transfer Execution foundation. Safety: - explicit execute mode required - dry-run remains default - protected tables require preservation checks - migration evidence report generated This phase provides execution framework only. Production PostgreSQL INSERT implementation r |
| `tools/postgres-transactional-import.py` | `PLANNED` scaffold — mini-SIEM PostgreSQL Transactional Import. Safety-first implementation stage. Current behavior: - connects only when explicitly configured - requires --execute for write mode - keeps transaction lifecycle explicit - protected tables require review This foundation does not automatically overwrite exi |
