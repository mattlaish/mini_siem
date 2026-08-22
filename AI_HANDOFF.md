# AI Development Handoff

## Project
Mini SIEM

## Objective
Continue development and improvement of the Mini SIEM platform.

## Current Status
The initial source import is intact. Per the maintainer, the platform is well
tested in practice: it has been exercised functionally end-to-end and is
considered stable for its intended use (the Sophos poller, for example, has run
in production — see Known Issues). That testing is manual/functional and lives
outside this repository — there is no automated test suite or CI checked in.
The standard-library ingestion/storage path additionally has a passing local
smoke baseline recorded below. Dashboard/Flask-dependent checks that a given
environment cannot run (e.g. Flask not installed) are environment gaps, not
product defects.

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
- The maintainer reports the platform is well tested through hands-on
  functional testing across ingestion, the dashboard, and its feature set.
  This is not yet captured as an automated, in-repo unit/integration suite;
  the repository's mechanical validation consists of `security_static_scan.py`,
  `security_dynamic_scan.py`, syntax compilation, and manual smoke tests.

## Completed
- Existing SIEM source imported and repository initialized.
- Repository exclusions and permanent AI instructions configured.
- Reviewed repository instructions, README, entry points, dependency list,
  configuration defaults, security scanners, and representative SQL flagged by
  the static scanner.
- Established a passing syntax and core-runtime baseline on 2026-08-17.
- 2026-08-21 session: re-read README.md, AGENTS.md, and AI_HANDOFF.md; confirmed
  project purpose, permanent working rules, and current state. Recorded the
  maintainer's assessment that the platform is well tested in practice, and
  captured a Proposed Feature Roadmap of substantial (non-bug-fix) next builds.
  Merged the concurrent `main` update (patch.md ledger, Sophos-poller and
  rule-state decisions) into this branch. No source code was changed this
  session; only handoff/ledger documentation was edited.

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
- Establishing the Flask/dashboard runtime and security-test baseline in
  environments that have `requirements.txt` installed.
- Selecting the first feature from the Proposed Feature Roadmap to implement.

## Known Issues and Gaps
- The active environment does not have the dependency from `requirements.txt`
  installed, so dashboard imports and the dynamic security scan are unverified.
- OAuth/OIDC and SAML flows have not been tested against live identity providers.
- PostgreSQL has not been tested against a live server.
- The platform is well tested manually/functionally per the maintainer, but
  that coverage is not yet encoded as an automated in-repo unit/integration
  suite, and no CI configuration is present. Codifying the existing manual
  coverage into an automated suite would guard against regressions.
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

## Proposed Feature Roadmap (candidate next builds)
Substantial feature work (not bug fixes) recommended for the platform. Each
notes what it is, why it matters, and where it fits the existing modules.

1. Alert case management / triage lifecycle.
   - What: give alerts a working state machine instead of fire-and-forget.
     Status (new -> acknowledged -> investigating -> closed), assignee,
     analyst notes/comments, and a disposition (true-positive / false-positive /
     benign) recorded back onto the alert. Add suppression/mute rules
     (silence a known-noisy source+rule for a chosen window).
   - Why: this is the largest workflow gap. Detection, enrichment, and AI
     triage already exist, but there is no way for an analyst to actually work
     an alert or to control alert-fatigue noise.
   - Where: extends the `alerts` table and the dashboard alert feed; audit the
     lifecycle transitions through the existing audit trail.

2. Sigma rule ingestion.
   - What: import the open-source Sigma detection ruleset and compile matching
     rules into the live engine, instead of hand-writing `Rule` subclasses.
   - Why: highest detection-coverage leverage; one feature multiplies the
     number of detections by orders of magnitude using community content.
   - Where: `rules.py` / `correlations.py` (a Sigma -> engine compiler plus a
     management surface for enabling/disabling imported rules).

3. GeoIP enrichment + impossible-travel detection.
   - What: enrich source IPs with geo/ASN at ingest using an offline MaxMind
     database (no external calls, consistent with the local-first design),
     expose country/ASN as searchable fields, and add an impossible-travel
     detection (same user authenticating from two locations too far apart to
     travel between in the elapsed time).
   - Why: a classic high-value SIEM detection the platform cannot currently do,
     and enrichment that improves search and correlation broadly.
   - Where: ingest/enrichment path alongside existing field materialization;
     new detection in the correlation/playbook layer.

4. Visual analytics overview page.
   - What: a dashboard landing view with charts - events/min time-series,
     top talkers, alert severity trend, alerts-over-time, and silent-source
     status - instead of only tabular log search and alert feeds.
   - Why: high-visibility overview that a real SIEM opens on; the data already
     lives in SQLite, so this is primarily a query + charting layer.
   - Where: new dashboard page/route querying existing tables; no new ingest
     pipeline required.

## Failed or Deferred Approaches
- Dashboard and dynamic security checks were attempted with the system
  `python3`, but Flask was unavailable. No dependency installation was performed
  during this inspection.

## Recommended Next Step
Because the maintainer considers the platform well tested and stable, the next
work is feature development rather than a test/CI catch-up. Pick one item from
the Proposed Feature Roadmap and implement it on the working branch. Suggested
starting point: item 1 (alert case management / triage lifecycle), the largest
analyst-workflow gap; item 2 (Sigma rule ingestion) is the alternative if
deepening detection coverage is the priority. Record the concrete work in
`patch.md` per the AGENTS.md ledger rule. Before merging any dashboard-side
work, run the Flask-dependent smoke checks (`dashboard.py`/`siem.py --help`,
`security_dynamic_scan.py`) in an environment with `requirements.txt` installed.

## Last Verified
- Runtime/test baseline: 2026-08-17 in `/Users/mattlai/Projects/mini_siem` at
  commit `fa41fc5` (`Initial import of Mini SIEM project`).
- Handoff update: 2026-08-21 (documentation-only; no code changed). Status,
  roadmap, and next-step guidance refreshed and merged with `main`.
