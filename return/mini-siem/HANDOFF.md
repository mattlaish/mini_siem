# mini-SIEM Dashboard connector return — 2026-10-22

This is a rebuilt, self-contained code-and-fixture return, not documentation only.
Authoritative source: `C:/Users/mattlai/Projects/mini_siem`. No Git operations,
production database changes, credential provisioning or Dashboard source changes
were performed. Missing connector files were recovered from the recorded October
4 delivery, reviewed, and integrated with the current October 17–18 source.
The old archive was not recovered and this is not claimed to be byte-identical.

## Contents and boundaries

- `source/`: complete safe application source, including current detection,
  templates and UI scripts, tests, connector, schemas and token-management tool.
  `SOURCE_MANIFEST.json` lists its exact repository-relative paths and hashes.
- Exact nine-field `adapter-manifest.fixture.json`; complete fixture binding and
  separate non-deployable binding template; five-field `fixture-bundle.json`.
- Four enabled read lanes: alerts, incidents, assets and health-observations.
  Events/audit-events/action-status remain disabled; actions remain empty.
- Real route-generated synthetic fixtures, 14 stage-aware negative cases,
  independent requests/evidence for 11 transport cases, old-revision positive
  sequence, reproducible tools, fresh logs and complete `SHA256SUMS`.
- Stable OWI-1.0 prefix `/api/integrations/dashboard/v1`, opaque bearer reader,
  dedicated management HTTPS 443 or approved same-host HTTPS 19406.
- Cursor schema/visibility drift now requires reset; snapshots are ordered by
  numeric export sequence, not lexical external IDs. Existing opaque cursors
  created before this rebuild require reset rather than silent reuse.

## Status — do not confuse offline receipt with production qualification

| State | Result and exact coverage |
|---|---|
| PRODUCT_API_LOCAL | PASS for synthetic SQLite auth/scope/rotation/rate/read-only, paging and current detection/UI regressions; not all R3 operational requirements |
| RETURN_PACKAGE | PASS only after the accompanying validator and final archive audit; all hashes must match |
| DASHBOARD_OFFLINE_ACCEPTANCE | PASS for 21-page/26-record/6-negative replay and all 14 decoder/page/sync negatives; central transport execution is NOT_RUN |
| LIVE_DEPLOYMENT | NOT_RUN; binding disabled, manifest UNQUALIFIED, no production registration |

G1 remains PARTIAL against the complete R3 operational specification. G2 offline
coverage does not imply G3. See `open-gaps.md` for implementation gaps as well as
environment-dependent work. A successful schema/fixture return is not authority
to enable a production integration.

## Reproduce from repository root

Use Python 3.12 and install `requirements-dev.txt` in an isolated environment;
`tzdata` is required on Windows. `<packet>` is the reviewed OWI packet root.
`<dashboard>` is an existing reviewed Dashboard checkout, read-only for this work.

```text
python -B return/mini-siem/tools/build_return_package.py --prepare --refresh-local-manifest
python -B return/mini-siem/tools/generate_fixture_bundle.py --contract-root <packet>
python -B return/mini-siem/tools/run_offline_checks.py --dashboard-root <dashboard> --tests
python -B return/mini-siem/tools/generate_fixture_bundle.py --contract-root <packet> --checksums-only
python -B return/mini-siem/tools/validate_return.py
python -B return/mini-siem/tools/build_return_package.py
```

The generator creates disposable SQLite state, uses synthetic TEST-NET hosts and
passes through the actual mapper/auth/routes. Tokens never enter the returned
files. Positive replay evidence starts NOT_RUN and becomes PASS only when the
existing Dashboard ReplayState executes it. Central CLI commands, exit codes,
consumer source hashes and binding/bundle identity are in
`test-logs/offline-checks.json` with stdout/stderr files.

For an extracted return, the outer `tools/generate_fixture_bundle.py` and
`tools/validate_return.py` discover the included `source/` automatically. The
source tree also includes its own return tools for independent rebuilding.

## Deployment / schema / owner responsibilities

Review and back up the target before replacing source. Preserve local runtime
configuration and credentials; they are intentionally not shipped. This return
adds five connector tables and their indexes through owner-run initialization.
Existing PostgreSQL runtime roles must not run DDL. Use the DB owner to initialize
and refresh the split-role grants before restarting runtime processes. See
`deployment.md` and `deployment-inputs.md`; do not run the web dashboard as root.

There is no second database or change to the Sophos poller, memory-only threshold
state, normalization or Windows detection logic. October 17 hardening and October
18 operator-facing changes are retained. Dashboard intake/review/pinning and all
live qualification remain with Dashboard/deployment owners; no central validator,
registry or copied fixture was changed by this rebuild.
