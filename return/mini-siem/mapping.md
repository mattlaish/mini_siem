# Native-to-wire mapping

| Native authority | Wire resource/field | Allowed, redacted or null | Revision trigger |
|---|---|---|---|
| `alerts.id` | ALERT `external_id=alert-{id}` | Stable numeric alias; no raw message | Alert/workflow canonical content changes |
| `alerts.rule_name` | ALERT `rule_id` | Safe native ID or stable SHA-256 alias | Rule identity changes |
| alert workflow | ALERT status and INCIDENT case | Assignee/note/AI text omitted | Workflow status/update changes |
| `alerts.log_ids` | provenance evidence refs | References only; raw log body omitted | Evidence membership changes |
| log hostname/source IP | ASSET identities | Observed identity only; no authoritative deletion | Identity/last-seen changes |
| `runtime_stats.listener_health` | HEALTH | Bounded numeric metrics; diagnostic detail omitted | Heartbeat state/metrics change |

ALERT uses HISTORY semantics; the persistent alert table is the authority.
INCIDENT, ASSET and HEALTH use STATE semantics. Assets derived from retained
observations do not assert deletion tombstones. Tenant namespace participates
in the exported asset identity, preventing cross-tenant equality from becoming
an authority claim. A shared or reused IP remains an observed identity and is
not treated as proof that two assets are the same.

Attention codes are `SIEM.CORRELATED_SECURITY_ALERT` and
`SIEM.COLLECTOR_GAP`. Missing/stale health cannot be exported as healthy.
