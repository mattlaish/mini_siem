# PostgreSQL Transactional Import Phase

## Objective

Move from migration planning into a controlled transactional import stage.

## Current status

The importer introduces:

- explicit execute intent
- transaction lifecycle tracking
- import ordering
- protected table handling

No automatic overwrite behavior exists.

## Protected tables

- users
- api_keys
- app_config
- audit_log

## Required final validation

- PostgreSQL connection test
- target schema validation
- duplicate detection
- row-by-row import verification
- commit/rollback evidence
- post-import integrity report

## Safety rule

Migration completion requires evidence, not only successful SQL execution.
