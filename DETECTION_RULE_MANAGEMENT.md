# Detection and Process Execution Monitoring

Updated: 2026-10-17 (Taiwan, UTC+8). Hardening: stored-config robustness and
engine isolation, short-name/FQDN host matching, broader web-shell defaults and
all-events field-match rules (see "Robustness" and "Rule behavior").

Status: `IMPLEMENTED_TESTING_DEFERRED`. Source, synthetic SQLite/API tests and
local browser workflows exist. Real Windows -> NXLog -> network -> deployed SIEM
-> external notification delivery and live PostgreSQL qualification remain required.

## Operator surfaces

- `/detection-rules`: list/toggle five existing built-ins; tune thresholds,
  windows and applicable severities; configure two process rules; create/edit/delete
  bounded field-match rules scoped to Windows process/script events or all events;
  simulate a JSON event or raw syslog line against a draft.
- `/execution-windows`: host profiles (short name or FQDN), groups, timezones and
  roles, calendars, expiring rule-specific exceptions, telemetry health and a list
  of Windows hosts sending process/script events without a profile.
- `/security-alerts`: recent process/script and telemetry alerts, occurrence
  counts, existing lifecycle transitions, normalized evidence and original hot
  events. Archived evidence remains accessible through archive-aware log search.
- `/ai`: retained call/token/error/retry statistics, model breakdown and recent
  calls, plus optional operator-entered USD rates per million tokens. Estimates
  use current rates across retained history, separate cached input, and count
  unpriced calls. They are not provider invoices and never assume a rate.

Signed-in users can read and simulate; administrators save detection settings and
AI rates. Existing analyst/admin permissions control alert workflow changes.
Configuration writes require the normal session and CSRF token. Custom conditions
cannot execute Python, SQL, arbitrary regex or outbound actions.

## Existing normalization is reused

`listener.parse_syslog`, `normalize.FieldIndexer`, source profiles and the existing
`log_fields` index remain the foundation. `windows_events.py` adds source-qualified
mapping: provider AND channel AND event ID must agree.

| Source | Kind | Useful fields |
| --- | --- | --- |
| Microsoft-Windows-Security-Auditing / Security / 4688 | process_creation | NewProcessName, ParentProcessName, NewProcessId, creator ProcessId, CommandLine, creator/target identity |
| Microsoft-Windows-Sysmon / Microsoft-Windows-Sysmon/Operational / 1 | process_creation | Image, ParentImage, process/parent PID and GUID, User, UtcTime |
| Microsoft-Windows-PowerShell or PowerShellCore / matching Operational channel / 4104 | script_execution | ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal |

Flat NXLog and structured System/EventData JSON are supported. Canonical fields
include host, provider/channel/record ID, event/receipt time and ingest delay,
process/parent path, name, PID and GUID, command line, creator/target SID and
domain-qualified name, user and script fields. Hex PIDs become decimal strings.
Missing command lines/parent images remain missing. Raw JSON is unchanged.

Canonical fields join the existing index and PostgreSQL Event Storage v2 typed
projection. Explicit reindex derives fields from saved raw JSON without replaying
rules, and refreshes PostgreSQL typed field metadata through its existing helper.
There is no automatic historical rewrite at startup.

Explicit timestamp offsets are converted to UTC; Sysmon UtcTime is UTC. Naive
timestamps require the exact host profile's IANA timezone. Ambiguous/nonexistent
DST wall times require an offset. Invalid time skips calendar decisions with an
explicit unknown simulation result; the unconditional web-shell rule still works.
Negative ingest delay exposes clock skew rather than changing event time.

Microsoft references: [4688 fields and command-line auditing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688),
[Sysmon process creation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[PowerShell script-block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows).

## Rule behavior

`web_server_shell`: default parents tomcat7-11.exe (Tomcat 8+ runs as the
`tomcatN.exe` Windows service), w3wp.exe and php-cgi.exe; default children are the
shells plus reconnaissance/living-off-the-land binaries a web shell often runs
directly (whoami, net/net1, nltest, systeminfo, certutil, bitsadmin, rundll32,
regsvr32, mshta, wscript, cscript, wmic, bash). csc.exe and conhost.exe are excluded
because IIS/ASP.NET spawn them legitimately. Critical at any hour. java.exe/httpd.exe
also require the host's `web_server` role. Saved configurations keep their own
lists; only new/unsaved configurations get the new defaults.
Parents/children and required role are editable. Calendar exceptions cannot exempt
this rule; administrators can explicitly toggle it. Office hours never suppress it.

`out_of_hours_shell`: shell creation outside a matching host/group window produces
High, stored as the existing `error` severity. Only configured calendars apply.
No calendar is shown as unconfigured and implies no company-wide default.
Office-hours events remain evidence and remain subject to other rules.

Custom `match` rules AND up to 12 conditions using `equals`, `contains` or glob.
Each rule has a `scope`: `windows` (default, and the behaviour of rules saved before
scopes existed) evaluates only Security 4688, Sysmon 1 and PowerShell 4104 events;
`all` also evaluates syslog, firewall, API and JSON events. Condition fields are the
Windows canonical fields, the generic `message`, `source.ip`, `host.name`,
`event.severity`, `app.name`, `log.format`, or any extracted key as `field.<name>`
(key=value pairs, JSON keys and custom-pattern named groups, e.g. `field.action`).
For example, combine `event.kind=script_execution` with a `script.text` substring,
or `field.action=deny` with a `message` substring for a firewall rule. All-events
matches on non-Windows events link into one alert per rule/host/source while they
keep firing (five-minute idle horizon, occurrences counted, 500 linked IDs), so a
noisy match cannot flood the alert table. Script fragments remain individual records;
fragment reassembly and a broad process graph are later extensions.

Built-in message patterns stay code-owned. NXLog triggers retain each source
event severity. Existing threshold counters remain in memory and reset on restart
as designed; changing a threshold/window clears its counters. Saved configuration
persists and reloads within five seconds.

## Calendars and exceptions

Calendars target hostnames or explicit groups. A short hostname (`HMSWEB1`)
matches the FQDN that domain-joined Windows reports in `Computer`
(`HMSWEB1.corp.example.com`) and vice versa; an exact profile wins, two different
FQDNs never match, IP addresses only match exactly, and a short name that matches
several FQDN profiles resolves to none rather than guessing a timezone or role.
The same matching applies to profiles, schedules, exceptions and telemetry. Monday=0 through Sunday=6;
start inclusive, end exclusive. Overnight windows use their starting weekday/date.
Additional dates support one-off windows; excluded dates support holidays including
the after-midnight part. Mark a maintenance window **exception-only** when it must
approve only a scoped job. An ordinary window approves all matching shells on its
target hosts during that period; an exception-only window never broadens that.

Exceptions match Windows process fields, so new saves only accept them for
`out_of_hours_shell`, `nxlog_severity_event`, `high_severity_event` and
Windows-scope custom rules (already-stored configurations remain loadable).
Exceptions require a specific rule, host/group, exact executable/parent paths,
command-line glob, exact account, calendar, offset-aware expiry and change ticket.
Blanket executable/parent/account globs are rejected. Expired exceptions do not
apply even to delayed events arriving after expiry. The authenticated administrator
is recorded as approver on changes. Each save atomically records full before/after,
actor, timestamp and revision in `audit_log`. Concurrent edits return HTTP 409.

## Alerts, evidence and notifications

New detections use existing `alerts` and linked event IDs. Existing AI triage,
ticket dispatcher and lifecycle consume them. Alert descriptions are escaped in
the main view; new evidence panels render text only. No second evidence DB exists.

Duplicate suppression retains at most 512 recent identities for a five-minute
receipt horizon. Matching requires the same rule/config revision, host, PID,
executable, parent PID and command line, with event times within two seconds.
This merges 4688/Sysmon evidence when enough identity agrees. Missing identity
produces separate alerts; this is not an exactly-once guarantee or process graph.
Resolved/closed alerts are not reused. Linked IDs are capped at 500 per alert;
occurrences continue counting and original events remain stored. Existing main
dashboard grouping provides host/rule burst display grouping.

Alert creation/duplicate linking is transactional, with a PostgreSQL row lock for
independent processes. Bounded replay metadata lives in `app_config`; raw logs
are never overwritten. Sophos OAuth/Whoami/token/cursor behavior is unchanged.

## Robustness

- A stored configuration from an older release is migrated on load: missing
  sections become empty and built-ins added later arrive with their defaults.
- If the stored configuration still cannot be loaded, the rule engine keeps its
  last good configuration and logs the error (once, then once a minute); the
  telemetry monitor skips its tick rather than pruning state against defaults;
  the Detection Rules page shows a warning with defaults carrying the stored
  revision so an administrator can review and save over it.
- `RuleEngine.process` never raises: a detection or alert-write failure is
  counted, logged and rolled back, so IOC matching, forwarding and ingest
  accounting that run after it continue for every event. One failed alert write
  no longer stops the event's remaining findings.
- Corrupt JSON in the detection state rows is replaced instead of blocking saves
  and alert writes.

## Telemetry expectations

Hosts opt into expected Security 4688, Sysmon 1 and/or PowerShell 4104 receipt.
The monitor checks every 15 seconds, persists per-host/source receipt and outage
state and emits one warning per silent period. Fresh matching events clear the
outage latch. Other channels/event IDs do not prove 4688 collection is healthy.
Stale monitor heartbeat is shown as unknown, never receiving/healthy. Observed
Windows hosts with no matching profile are kept (7 days, at most 200) and listed on
`/execution-windows` with a one-click "Add profile".

Choose silence thresholds appropriate for expected activity. Idle hosts may emit
no process/script events; use a controlled regular source test/heartbeat where
needed. Receipt monitoring cannot prove lossless UDP delivery. Process events
cannot capture every internal command typed into an already running shell.

## Deployment and API

Install updated `requirements.txt` (`tzdata` added), replace the complete source,
templates and static assets, and restart listener/dashboard. No schema migration,
additional database or runtime DDL privilege is introduced. Do not replace only
dashboard.py; the new modules/assets are required.

Machine HTTP ingestion now reaches API-key validation without a browser session
and preserves Windows JSON. Standalone dashboard and async listener ingestion run
rules after storage. Other request-size/security backlog stays separately scoped.

APIs: `GET/PUT /api/detection/config` (GET adds `load_warning` when the stored copy
was rejected), `POST /api/detection/simulate` (`{"event": {...}}` or `{"raw": "..."}`),
`GET /api/detection/telemetry`, `GET /api/detection/unprofiled-hosts`,
`GET /api/detection/alerts`,
`GET /api/detection/alerts/<id>/evidence`, existing `GET /api/ai/usage`,
and admin `PUT /api/ai/usage/rates`.
Unused `POST /api/correlate` and `POST /api/normalize` now return 404. Active
investigate/playbook/norm-pattern/field/reindex flows remain available.
