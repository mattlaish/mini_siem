# Operator experience and product language review

Updated: 2026-10-18, Taiwan (UTC+8).

## Scope and current assessment

Authoritative source: `C:\Users\mattlai\Projects\mini_siem`.
This pass read/scanned all 376 safe text files present at the initial audit,
then rechecked the updated tree (377 including the new regression test).
Credentials, environment secrets, databases, Git internals, binary archives and
dependency/cache directories were excluded. This is a whole-tree wording scan
plus focused source and browser review, not qualification of every documented
feature or an assertion that every historical document describes current code.

The October 17 detection hardening and October 18 alert-queue/smart-refresh work
are retained. The main remaining experience problem was the gap between a task
an operator wants to perform and implementation-oriented labels and forms.

## Implemented in this pass

| Previous wording | Operator wording |
| --- | --- |
| Correlate | Investigations |
| Execution Windows | Approved Hours |
| Audit | Activity History |
| Setup | Settings |
| API poller connectors | Cloud log connections |
| Syslog troubleshoot | Check log delivery |
| Source field mapping | Log field mapping |
| Search field aliases | Search across log sources |
| Re-index existing logs | Update fields in earlier logs |
| SIEM data plane / Runtime health | Collected logs and alerts / Service health |
| Runtime DDL / schema readiness | Application table-structure access / database upgrade checks |
| Telemetry health | Expected log delivery |
| Support bundle | Support report |

- Shared display labels cover known rule identifiers, key evidence fields and
  service/status codes without changing their underlying values. Unknown custom
  names are preserved. Unknown/overdue states never become Healthy. Alert severity
  `error` displays as High where used as alert importance; original log levels and
  failed-request Error states are not rewritten to High.
- Weekdays and expected Windows activity use named checkboxes; saved weekday
  integers and source identifiers are unchanged. Exception editors select supported
  rules and named approved windows, rather than requiring internal IDs. Missing
  references remain visible for correction, not silently replaced.
- Internal generated references are hidden while kept in form data. Draft/save
  feedback is explicit; reloading over unsaved edits asks for confirmation.
- The sample tester shows matched rules and limitations first, with original JSON
  results available under an optional details section. It still does not persist
  events or test multi-event repeated-activity rules.
- AI connection setup stays usable while AI is off. Analysis/chat remain disabled
  until enabled; this fixes the previous instruction to configure a connection
  while the entire settings area was non-interactive. Usage remains independently
  readable and has an explicit empty state.
- Help now follows tasks: connect a source, confirm arrival, review alerts, search
  evidence, configure rules/hours and investigate related activity. It no longer
  implies every alert requires multiple events or that cloud collection guarantees
  no loss/duplicates.

## Deliberately preserved technical information

Do not rename routes, JSON fields, stored rule identifiers, request parameters,
syslog levels, provider header names, protocol names or evidence. Operators still
need exact values such as X-Tenant-ID, OAuth2, JSON, source field names and vendor
URLs when connecting a product. Advanced setup and support details may use these
terms with explanations. Engineering handoffs, code comments, migration records,
original log messages and audit evidence remain accurate rather than euphemized.

## Next experience improvements (not implemented here)

1. **Guided source setup and verification.** Offer provider presets, connection
   validation, one sample event and a clear receiving/not-confirmed result in one
   workflow. The current cloud form still asks for several provider-specific fields.
2. **Role-aware progressive settings.** Separate day-to-day analyst controls from
   advanced administration; show read-only explanations before a user encounters a
   rejected save. Keep backend permission checks authoritative.
3. **Visual rule/search building.** Provide field descriptions and a searchable
   field picker, host-role choices and a time-zone picker. Exact field names and
   free-text time zones still require background knowledge today.
4. **Compact small-screen navigation.** The Settings section list occupies much of
   a narrow screen before the form. Use a compact section picker and stack long
   provider fields; preserve evidence readability and keyboard focus.
5. **Uniform recovery feedback.** Several legacy page requests still need a shared
   loading/error/retry pattern. A failed refresh must not look like an empty or
   healthy result; retain useful support detail behind an optional disclosure.

These are product workflow follow-ups, not promises that another detection
framework, SOAR or a second database is needed.

## Verification and limits

- Same-environment Windows/Python 3.12 comparison, actual Projects source:
  before 306 passed / 47 failed / 3 skipped; after 323 passed / same 47 failed /
  3 skipped. No new failing test identities. This is not a fully green suite.
- New product-language coverage: 17 passed, including labels, role-aware page
  rendering, provider option values, original evidence and calendar request schema.
- Three older static-copy assertions were updated to the new labels/wording;
  their endpoint, no-custom-filter and maintenance-privilege assertions remain.
- Syntax: 145 Python files, five static JS files and seven rendered inline JS
  blocks; 11 authenticated routes rendered. Placeholder truth gate passed.
- Before/after comparison found no missing existing template control IDs and no
  changes to explicit select-option values. Source evidence is not translated.
- Browser QA used an isolated loopback preview importing Projects source, synthetic
  events and a disposable database: weekday draft/save round trip, readable rule
  names and severity, sample-result summary, Sophos field switching, AI-off setup
  access and settings copy. Captured browser error log was empty. Small-screen
  screenshot review exposed the navigation follow-up above.
- No live PostgreSQL, Windows/NXLog/provider delivery, production browser session
  or external AI request was used. No production service, ACL or credential change,
  no Git command, and no new delivery ZIP. External validation files and backups
  remain outside application source.

Reproduce with `python -m pytest tests/test_product_language.py` and the normal
project test environment. Linux-only systemd qualification does not collect on
this Windows host. The local 47-failure baseline must not be substituted for the
different environment's historical 38-failure result in the earlier handoff.
