# Investigation Operations Guide

## Purpose

This document describes the active SOC operating model for mini-SIEM investigations. As of 2026-09-01, the Short/Medium/Long profile workflow is **implemented in runtime**: Short is always analyzed first, Medium runs only after a no-suspicion/insufficient Short result, and Long runs only after the same result at Medium.

## The two questions operators must keep separate

### 1. What triggered the investigation?

The trigger is source/rule specific.

- NXLog Windows: warning/error-or-higher events may trigger according to the NXLog policy.
- API/poller: uses its own existing trigger rules.
- Firewall: uses its own firewall/detection rules; firewall warning/error must not be treated as NXLog warning/error simply because the severity labels look similar.

### 2. What is related to the investigation?

After a legitimate trigger, related evidence can come from any telemetry source and any severity when it is linked to the investigated entity.

For an IP investigation, the same IP may be relevant as:

- source
- destination
- peer
- endpoint IP
- normalized or extracted source/destination field

This means an NXLog-triggered investigation can legitimately contain FortiGate, Sophos/API, or other logs as related evidence. "Firewall does not use the NXLog trigger rule" does **not** mean "firewall cannot be related evidence."

## Progressive investigation procedure

The runtime workflow is intentionally staged:

```text
SHORT -> ask LLM -> suspicious evidence?
             | yes: stop widening and report/analyze
             | no / insufficient
             v
MEDIUM -> ask LLM -> suspicious evidence?
              | yes: stop widening and report/analyze
              | no / insufficient
              v
LONG -> ask LLM -> final analysis/no-finding
```

The system calls the LLM with **Short evidence first only**. It does not pre-load Medium or Long evidence into the first call.

Medium is retrieved and analyzed only when the Short result returns `NO_SUSPICIOUS` or `INSUFFICIENT` (or omits the required decision marker, which fails open as `INSUFFICIENT`).

Long is retrieved and analyzed only when Medium returns the same no-finding/insufficient result. `SUSPICIOUS` at Short or Medium stops widening immediately.

If suspicious evidence is found at Short or Medium, profile expansion stops. Operators should see the evidence that caused the expansion to stop.

Manual triage uses the same progression as background auto-triage; manually selecting an alert does not bypass Short/Medium/Long gating.

## Initial profile windows

| Investigation class | Short | Medium | Long |
| --- | --- | --- | --- |
| NXLog 4625 failed logon / authentication anomaly | 5m before / 10m after | 15m before / 30m after | 1h before / 2h after |
| Malware / Sophos detection | 2h before / 1h after | 6h before / 3h after | 24h before / 12h after |
| IOC hit | 4h before / 1h after | 12h before / 3h after | 48h before / 12h after |
| Account creation / privilege change | 15m before / 1h after | 45m before / 3h after | 3h before / 10h after |
| Firewall C2 / beaconing investigation | 1h before / 30m after | 3h before / 90m after | 12h before / 5h after |

These are investigation defaults, not firewall/NXLog severity mappings. They may be tuned with evidence after runtime telemetry is available.

## What the LLM should receive

The LLM evidence package should contain bounded, ranked evidence rather than all matching logs.

For each profile, include:

- trigger summary and trigger source
- investigated entity/entities
- profile name (`short`, `medium`, `long`)
- profile time bounds
- related events from all relevant sources
- source and destination direction where known
- severity and original event type without using severity as the relatedness gate
- deduplicated/reduced repeated events
- source-specific important fields
- evidence provenance so the analyst can tell NXLog, firewall, Sophos/API, and other sources apart

## Long-profile operating expectation

Long investigations are specifically for behavior that may not be obvious in a small local window. They must emphasize patterns rather than raw volume.

For repetitive traffic, provide summaries such as:

```text
First seen: 01:02
Last seen: 09:01
Count: 480
Median interval: ~60 seconds
Source: 192.168.1.50
Destination: 185.x.x.x:443
Representative events: 5
```

Do not send hundreds of effectively identical firewall rows simply because Long searches a larger period.

## Operational stopping rules

- Short finds suspicious/relevant evidence -> do not widen automatically.
- Short is clean/insufficient -> widen to Medium.
- Medium finds suspicious/relevant evidence -> do not widen automatically.
- Medium is clean/insufficient -> widen to Long.
- Long is the terminal profile for this workflow; produce the final analysis/no-finding disposition.
- A different deterministic playbook or explicit analyst action may start a new investigation with a different class/profile.

## Runtime observability

The runtime currently records the following stage provenance inside `alerts.ai_analysis`; a dedicated UI timeline remains a future enhancement:

- investigation profile/class and each stage actually executed
- stage time bounds
- candidate count and evidence count
- machine-readable LLM decision
- model analysis for each stage
- final stage used

The prompt itself includes trigger details, investigated IP, source/destination-aware related evidence, and escalation reason. Dedicated normalized DB columns/audit events for each transition are not yet implemented.

An operator must be able to distinguish "no suspicious evidence was found in Short" from "Short had no useful telemetry available."

## Safety and cost controls

- Never run Medium/Long merely because a timer expired; expansion follows the prior analysis disposition.
- Never run all three profiles by default.
- Keep related evidence cross-source, but preserve source identity in the evidence package.
- Keep firewall trigger policy independent from NXLog trigger policy.
- Apply deduplication and pattern summarization before Long-profile LLM calls.
- The LLM analyzes evidence; it does not receive unrestricted database query authority from this profile mechanism.


### Immediate-triage timing note

Auto-triage does not wait for the configured future half of a profile window to elapse. If a stage is analyzed before its full after-trigger window exists, retrieval uses evidence available through the current time. Operators should understand that a later manual/replayed investigation may have additional post-trigger telemetry.

## Upgrading a deployed instance (after `git pull`)

A code pull alone does not update the service environment. New releases can add
Python dependencies (for example the dashboard now serves via `waitress`), and a
missing dependency makes the service crash-loop on start. After pulling new code
on a host, re-provision before restarting:

```bash
cd /opt/mini_siem            # your install directory
git pull
sudo ./install-services.sh   # reinstalls venv deps, fixes perms, rewrites units
sudo systemctl restart mini-siem-listener mini-siem-dashboard
systemctl status mini-siem-dashboard
```

Re-running `install-services.sh` is safe and idempotent: it repairs the venv
(Flask + Waitress, and psycopg2 when `db-config.json` selects PostgreSQL),
tightens config-file permissions, and re-checks that the service account can
both import the required modules and resolve the intended DB backend.

PostgreSQL notes:
- `psycopg2` is an optional driver and is **not** in `requirements.txt`; the
  installer provisions it automatically when `db-config.json` selects postgres.
- `db-config.json` must be readable by the service account or the dashboard
  silently falls back to SQLite (`[db] backend: sqlite://siem.db` in the log).
  The installer now fails loudly if the service user cannot resolve postgres.
- `db-config.json` is environment-specific: verify its backend after any pull,
  since it carries your live connection settings.

## PostgreSQL raw-log privilege check

After provisioning or upgrading a PostgreSQL deployment, verify the evidence boundary:

```bash
cd /opt/mini_siem
./.venv/bin/python3 tools/postgres_privilege_check.py --db-config ./db-config.json
```

Expected:

```text
listener     ... select=True insert=True delete=False update=False truncate=False guards=2 => PASS
dashboard    ... select=True insert=True delete=False update=False truncate=False guards=2 => PASS
maintenance  ... select=True insert=True delete=True  update=False truncate=False guards=2 => PASS
```

If listener/dashboard report DELETE, UPDATE, or TRUNCATE capability, treat it as a security configuration failure and do not consider the deployment production-ready.

For a manual archive/move cycle under the secure boundary, use the maintenance identity:

```bash
python3 tools/archive_now.py --config ./db-config.json \
  --db-credentials ./db-maintenance-credentials.json
```

## Setup -> Troubleshoot: confirm syslog reaches the host

Administrators can open **Setup -> Troubleshoot**, enter the sender IP, and run a fixed 4-second packet-header capture. The check is limited to the currently configured syslog listen ports and reports whether matching UDP/TCP packets were seen.

Interpretation:

- **Syslog traffic seen**: network packets from that IP reached the SIEM host/listen port. Continue troubleshooting parser/storage if events still do not appear in Live Logs.
- **No matching packets**: verify sender destination IP, UDP/TCP choice, firewall/routing, NAT/source IP, and listener port configuration.

The capture does not display syslog payloads. It requires `tcpdump` and the root-owned helper installed by `sudo ./install-services.sh`.


## PostgreSQL Runtime Failure Mode

If listener/dashboard refuses startup because of missing tables or pending migrations:

Do not grant DDL permissions to runtime accounts.

Procedure:

1. Stop runtime services.
2. Run owner migration/init operation.
3. Verify schema_migrations.
4. Restart runtime services.

## Web Console observability and archive maintenance

Health now has three operator surfaces: Runtime Health, PostgreSQL Security & Schema Readiness, and Archive & Maintenance. PostgreSQL/archive security details are admin-only and read-only.

A STALE listener heartbeat means the dashboard has not seen a fresh listener heartbeat in the operational window. Diagnose the listener with systemd/journal; do not grant DB DDL or maintenance privileges to the dashboard.

Restart listener after Setup listen-port changes with:

```bash
sudo systemctl restart mini-siem-listener
```

Archive execution stays outside the Web Console. Use the maintenance identity:

```bash
python3 tools/archive_now.py --config ./db-config.json \
  --db-credentials ./db-maintenance-credentials.json
```

Verify catalog checksums with:

```bash
python3 tools/archive_verify.py --config ./db-config.json --json
```

The verification tool records an operational `archive_verify_status` when its selected DB identity has permission to update runtime status. The segment checksum/catalog remains the evidence source of truth.

## Incident diagnostics workflow

Use **Health -> Incident diagnostics** for the consolidated, read-only component view. A status includes the reason and an operator recommendation. The page cannot perform service restarts, schema repair or privilege changes.

For a source-specific syslog incident, use **Setup -> Troubleshoot**, enter the source IP, and run the four-second capture. The result reports Network, Listener, Parser, Storage and Search evidence separately. `UNKNOWN` means available telemetry cannot prove the stage; it is not equivalent to PASS or FAIL.

For escalation, an administrator can use **Setup -> Support bundle**. The generated `.tar.gz` includes health/diagnostics, runtime state, PostgreSQL/schema/security status, archive status, sanitized configuration summary and bounded systemd state. It deliberately excludes credentials, raw logs and service journals. Audit records are written when explicit diagnostics/support/pipeline actions run.


## Phase 12.2 — Installation / Upgrade Workflow

Status: IMPLEMENTED_TESTING_DEFERRED

Added:
- fresh installation workflow
- upgrade procedure
- migration ownership
- backup requirement
- rollback policy
- service restart ordering

## Recovery Operations

Backup and restore are operator workflows. Runtime services do not repair schemas.


## Phase 12.4 Performance & Capacity Qualification
Status: IMPLEMENTED_TESTING_DEFERRED
