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
- Live socket ingestion, long-running workers, external AI providers, generic
  API pollers, forwarding targets, and scheduled threat-intelligence retrieval
  were not exercised in this local baseline. The Sophos poller is an exception:
  it is fully implemented and user-confirmed working in production. From
  2026-08-05 through 2026-08-20 it continuously pulled 4,739 real Sophos API
  events. It was not independently revalidated during this local baseline.
- TCP ingestion assumes newline-delimited messages rather than RFC6587
  octet-counted framing.

## Important Decisions
- GitHub is the shared source of truth.
- Codex and Claude may both work on this repository.
- `AGENTS.md` contains permanent working instructions; this file tracks changing
  development state.
- `patch.md` is the persistent implementation and validation ledger. Every
  material AI-assisted change must update it in the same work session.
  `AI_HANDOFF.md` remains the concise current-state/design handoff, while
  `patch.md` records concrete patches, deployment notes, validation, and planned
  slices.
- Continue using temporary databases for destructive or authentication-changing
  tests. Do not point `security_dynamic_scan.py` at production data.
- Treat the static scanner as advisory: trace flagged dynamic SQL to its source
  rather than changing safe placeholder construction merely to silence it.
- Live-rule sliding-window state is intentionally memory-only and resets when
  the listener restarts. Stored logs and generated alerts remain persistent;
  historical detection across restarts is handled by database-backed
  correlation playbooks. Do not add rule-state persistence unless this design
  is explicitly changed.
- The working Sophos Central poller design is intentional: use the
  `oauth2_sophos` scheme, exchange the configured client ID/secret at
  `https://id.sophos.com/api/v2/oauth2/token` with scope `token`, pass the JWT
  as `Authorization: Bearer <token>` to
  `https://api.central.sophos.com/whoami/v1`, discover the tenant ID and
  `apiHosts.dataRegion`, then request the path-only `/siem/v1/events` with the
  JWT and automatically selected `X-Tenant-ID` header. Access tokens are
  intentionally cached in memory and refreshed before their assumed expiry;
  the event cursor is persisted in the database so polling resumes without
  starting over. The client secret is stored encrypted in the SIEM database.
  Preserve this verified integration flow unless a change is explicitly
  requested and tested against Sophos.

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
