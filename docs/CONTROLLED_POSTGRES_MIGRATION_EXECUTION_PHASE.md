# Controlled PostgreSQL Migration Execution Phase

## Objective

Move from validation unlock into controlled migration execution.

## Added

- approval input boundary
- execution workflow
- transaction evidence structure
- migration ordering
- final evidence tracking

## Safety

Execution requires explicit approval.

Protected identity tables remain separated:

- users
- api_keys
- app_config
- audit_log

## Current limitation

This phase establishes controlled execution flow.

Production migration still requires:

- enabled PostgreSQL writers
- validated credentials
- backup confirmation
- rollback verification
- post-import verification

## Evidence required

- transaction result
- table import result
- row comparison
- identity preservation
- integrity validation
