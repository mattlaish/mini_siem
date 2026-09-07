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

## Performance, archive, and overload operations

### Evidence lifecycle is archive-first

Do not configure time-based deletion of SIEM evidence. The supported lifecycle is:

1. keep recent events in the hot database;
2. copy eligible events into a sealed archive segment;
3. compact and SHA-256 checksum the segment and write its manifest;
4. catalog and re-open verify the segment;
5. only in `mode=move`, evict the verified hot copy.

`mode=copy` is the safer commissioning mode. `mode=move` reduces hot-database size while
keeping the original global log IDs searchable in the archive tier. Exact deduplication
stores an identical event payload/field set once per segment but preserves every
occurrence ID and receive time. Do not broaden this into fuzzy/semantic deletion: two
similar 4625s can be meaningful precisely because they happened twice.

Run archive integrity verification periodically and back up the archive directory in
addition to the hot database. A missing/corrupt expected segment is an evidence
availability incident; Log Search must report it explicitly rather than silently
returning a partial/empty history.

### SQLite maintenance

Online maintenance is non-destructive: PASSIVE WAL checkpoint above the configured
threshold, incremental free-page reclamation only when the DB already uses
`auto_vacuum=INCREMENTAL`, `PRAGMA optimize`, and rate-limited `PRAGMA quick_check`.
Never replace this with a live full `VACUUM` or an unbounded delete.

### Operational health states

The top Dashboard status and Health page derive one of:

- `HEALTHY` — queues/latencies are below warning thresholds and no recent interval
  failure/drop signal is present.
- `DEGRADED` — a queue or latency is near its configured warning threshold, or telemetry
  is stale enough to reduce confidence.
- `OVERLOADED` — a queue is near capacity or a recent interval reports queue drops.

The API also returns the individual queue pressure signals and thresholds that produced
the state. This is observability only: health does not autonomously throttle or discard
logs.

### Query telemetry truth boundary

Query telemetry records only allowlisted coarse classes and timing statistics. It must
not include search text, field values, IP/host filters, usernames, SQL parameters, or
other sensitive/high-cardinality data. Telemetry failure is fail-open and cannot change
query predicates, cursors, result limits, or archive inclusion. If archive evidence is
expected but unavailable, the query itself fails explicitly rather than pretending that
zero rows matched.

### IOC architecture decision remains open

The current IOC matcher remains in service. Phase 6 makes no further architectural
commitment about whether IOC stays embedded or becomes a separate enrichment service.
Do not remove or further couple IOC behavior merely as part of archive maintenance.

### PostgreSQL validation

The bounded PostgreSQL pool/session configuration remains implemented, but production
plan validation must be run against a disposable PostgreSQL instance before claiming
that backend as validated. See `TESTING.md` for the exact command and current deferred
gates.

