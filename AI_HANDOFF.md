# AI Development Handoff

## Project
Mini SIEM

## Objective
Continue development and improvement of the Mini SIEM platform.

## Current Status
The initial source import is intact and the Git worktree was clean before this
handoff update. The standard-library ingestion/storage path has a passing local
baseline. Dashboard-dependent validation is currently blocked because Flask is
not installed in the active Python environment.

## Architecture Baseline
- `siem.py` is the combined entry point for syslog listeners and the Flask
  dashboard; `listener.py` and `dashboard.py` can also run separately.
- Syslog ingestion supports UDP/TCP, parses RFC3164/RFC5424-style messages,
  stores events through the abstraction in `db.py`, and invokes live rules,
  IOC matching, field indexing, and forwarding.
- SQLite is the default tested backend. PostgreSQL support is implemented but
  still requires validation against a real PostgreSQL instance.
- The dashboard includes local authentication, optional OAuth/SAML, CSRF
  protection, log search, retrospective correlations/playbooks, health and
  audit views, AI triage, API polling, threat-intelligence feeds, API-key
  ingestion, and administration/configuration endpoints.
- There is no conventional unit-test suite. Validation currently consists of
  `security_static_scan.py`, `security_dynamic_scan.py`, syntax compilation,
  and manual smoke tests.

## Completed
- Existing SIEM source imported and repository initialized.
- Repository exclusions and permanent AI instructions configured.
- Reviewed repository instructions, README, entry points, dependency list,
  configuration defaults, security scanners, and representative SQL flagged by
  the static scanner.
- Established a passing syntax and core-runtime baseline on 2026-08-17.

## Test and Review Results (2026-08-17)
- `python3 -m compileall -q .`: PASS (bytecode redirected outside the repo).
- Core temporary-SQLite smoke test: PASS. Verified schema initialization,
  RFC3164 parsing, log insertion, rule processing, field indexing, IOC matching,
  a stored log count, and `secretbox` encrypt/decrypt round-trip.
- `python3 listener.py --help`: PASS.
- `python3 security_static_scan.py --json`: completed successfully; 19 Python
  modules scanned and 12 HIGH pattern findings reported. Manual inspection found
  the flagged SQL to use generated parameter placeholders, fixed internal
  clauses, or allowlisted identifiers. No confirmed SQL injection was identified,
  but these remain advisory findings rather than proof of full security.
- `python3 security_dynamic_scan.py`: NOT RUN to completion; import stopped with
  `No module named 'flask'` (exit 2).
- `python3 siem.py --help` and `python3 dashboard.py --help`: BLOCKED by the same
  missing Flask dependency. The listener CLI does not require Flask and passed.
- No project files or configured `siem.db` were touched by tests; temporary
  databases were used.

## In Progress
- Establishing the Flask/dashboard runtime and security-test baseline.

## Known Issues and Gaps
- The active environment does not have the dependency from `requirements.txt`
  installed, so dashboard imports and the dynamic security scan are unverified.
- OAuth/OIDC and SAML flows have not been tested against live identity providers.
- PostgreSQL has not been tested against a live server.
- No automated unit/integration test suite or CI configuration is present.
- Live socket ingestion, long-running workers, external AI providers, API
  pollers, forwarding targets, and scheduled threat-intelligence retrieval were
  not exercised in this baseline.
- The live rule engine keeps sliding-window state in memory, so state resets on
  restart. TCP ingestion assumes newline-delimited messages rather than RFC6587
  octet-counted framing.

## Important Decisions
- GitHub is the shared source of truth.
- Codex and Claude may both work on this repository.
- `AGENTS.md` contains permanent working instructions; this file tracks changing
  development state.
- Continue using temporary databases for destructive or authentication-changing
  tests. Do not point `security_dynamic_scan.py` at production data.
- Treat the static scanner as advisory: trace flagged dynamic SQL to its source
  rather than changing safe placeholder construction merely to silence it.

## Failed or Deferred Approaches
- Dashboard and dynamic security checks were attempted with the system
  `python3`, but Flask was unavailable. No dependency installation was performed
  during this inspection.

## Recommended Next Step
Create or activate an isolated virtual environment, install
`requirements.txt`, then rerun `security_dynamic_scan.py` and the dashboard and
combined-entry-point help smoke tests. If those pass, add a small automated test
suite around parsing, database initialization/storage, authentication/CSRF, and
the highest-risk API query paths, then wire it into CI.

## Last Verified
2026-08-17 in `/Users/mattlai/Projects/mini_siem` at commit `fa41fc5`
(`Initial import of Mini SIEM project`).
