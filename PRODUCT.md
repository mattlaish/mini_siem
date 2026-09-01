# Product Behavior

## Progressive AI Investigation

mini-SIEM investigates alerts in progressively wider context instead of either sending too little telemetry or immediately sending a large historical dump to the LLM.

The product model is:

> **Trigger decides when to investigate. Related decides what evidence belongs to that investigation. Profile escalation decides how far back/forward to search.**

These are separate concepts and must remain separate in the product.

## Trigger behavior

Source-specific trigger policies remain independent:

- NXLog Windows warning/error-or-higher events can be investigation triggers.
- API/poller detections use their own trigger rules.
- Firewall keeps its own detection/trigger behavior. NXLog warning/error semantics must not be applied to firewall events just because both use normalized severity labels.

This avoids further mixing already heterogeneous severity semantics across products.

## Related evidence behavior

Once a valid trigger starts an investigation, the product looks across telemetry sources for evidence related to the investigated entity.

For IP-based investigations, related evidence includes the IP when it appears as a source **or** destination, plus endpoint/peer/normalized source-destination roles where available.

Therefore an NXLog-triggered investigation may include:

- NXLog informational/notice/warning/error events
- FortiGate/firewall traffic where the IP is source or destination
- Sophos/API endpoint events for the same IP
- other syslog/API telemetry tied to that IP

Related evidence is not restricted to the trigger source and is not restricted by severity.

## Three investigation profiles

### Short

Fast, local context around the trigger. Designed to answer common cases with the smallest useful evidence package.

### Medium

A wider search, normally around 3x the Short scope for the same investigation class. It is used **only if the Short LLM analysis finds no suspicious/relevant evidence or determines that the evidence is insufficient**.

### Long

A historical/pattern-oriented search, normally around 10x the Short scope for the investigation class. It is used **only if Medium also finds no suspicious/relevant evidence or remains insufficient**.

The product must not run all three profiles for every alert. Automatic and manual triage share this state machine.

## Product escalation experience

```text
Trigger
  -> Short evidence
  -> LLM
      -> suspicious/relevant evidence found: finish investigation at Short
      -> no suspicious evidence / insufficient: expand to Medium
  -> Medium evidence
  -> LLM
      -> suspicious/relevant evidence found: finish investigation at Medium
      -> no suspicious evidence / insufficient: expand to Long
  -> Long evidence
  -> LLM
      -> final finding or no-finding conclusion
```

This provides three benefits:

1. Routine events remain fast and inexpensive.
2. More difficult incidents gain additional context automatically instead of being prematurely marked clean.
3. Long investigations can focus on patterns and history without overwhelming every LLM call with unnecessary data.

## Initial profile defaults

| Investigation class | Short | Medium | Long |
| --- | --- | --- | --- |
| NXLog 4625 failed logon / authentication anomaly | 5m before / 10m after | 15m before / 30m after | 1h before / 2h after |
| Malware / Sophos detection | 2h before / 1h after | 6h before / 3h after | 24h before / 12h after |
| IOC hit | 4h before / 1h after | 12h before / 3h after | 48h before / 12h after |
| Account creation / privilege change | 15m before / 1h after | 45m before / 3h after | 3h before / 10h after |
| Firewall C2 / beaconing investigation | 1h before / 30m after | 3h before / 90m after | 12h before / 5h after |

These defaults are intentionally investigation-specific. A single global `30 minutes` or `latest 40 events` rule is not an adequate product definition of relatedness.

Profile windows are centered on the linked trigger-event time when available, not merely when the alert row was created. Auto-triage does not deliberately wait for future telemetry: the after-trigger side of a window uses evidence available up to analysis time.

## Evidence quality

The product should present the LLM with an evidence set, not a raw log dump.

Short and Medium should rank direct entity relationships and temporal relevance. Long should additionally summarize repetition and periodicity. For example, a beacon-like pattern should be represented by count, first/last seen, interval statistics, destination, and representative events instead of hundreds of duplicate firewall rows.

## Analyst visibility

The stored AI analysis now preserves profile progression. A dedicated visual investigation timeline should later surface:

- Trigger source and event
- Investigated entity
- Current profile
- Why the profile escalated
- Sources included in related evidence
- Number of candidate events and reduced evidence items
- Whether suspicious evidence was found at Short, Medium, or Long
- Final LLM conclusion

The analyst should never have to infer whether Long was used because the system found something suspicious or because earlier evidence was insufficient.

## Status

The corrected trigger-vs-related behavior and the **Short -> Medium -> Long progressive LLM investigation workflow are implemented in the current runtime**. Short is always the first LLM stage. Medium runs only after `NO_SUSPICIOUS`/`INSUFFICIENT`; Long runs only after the same outcome at Medium. `SUSPICIOUS` stops widening. Missing decision markers are treated as insufficient so the system does not stop early by accident.

Current related investigation is IP-centered and cross-source/cross-severity. Dedicated UI visualization and broader multi-entity one-hop expansion remain future product enhancements.
