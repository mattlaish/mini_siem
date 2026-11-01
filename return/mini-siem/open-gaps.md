# Open gaps — explicit scope, not a production approval

## Implementation work still required for full R3/G1

- O-03: the recovered reader has rate/concurrency and snapshot quotas, but no
  complete server-wide deadline/cancellation/cleanup implementation. Do not label
  this as merely a missing TLS environment. Slow-source/lock/cancel qualification
  and deadline enforcement remain product work.
- O-04: new-client cursor continuation is covered, not a true killed independent
  process. Fault/kill boundaries, concurrent refresh/sequence allocation and
  retention-gap handling need implementation review and executable coverage.
  The export index stores each object's latest revision, not a full revision
  outbox; intermediate lifecycle revisions can be coalesced.
- Native mini-SIEM has a single database authority, not per-tenant row ownership.
  Token tenant namespaces and cursor binding are tested; native multi-tenant
  visibility isolation is NOT established. Do not provision different customers
  into the same native authority and claim tenant-isolated exports.
- The asset mapper groups retained observations using observed IP/hostname; this
  is not a durable device inventory or proof against shared-IP/DHCP reuse. Do not
  use these aliases for automatic authoritative cross-product identity merges.
- O-06: rule version is null; original third-party forwarding provenance is not
  fully reconstructed. Per-code positive/insufficient-evidence examples and
  retention/notification-suppression truth require more native-mapper coverage.
- Disabled HISTORY lanes retain the earlier consumer-compatibility value 30 in
  discovery. This is not a claim that disabled event/audit lanes retain/export
  data; C-03 semantics remain a Dashboard/product contract follow-up.

## Environment-dependent / NOT_RUN

- T-TIMEOUT: real transport cancellation/deadline; independent request fixture and
  explicit NOT_RUN evidence provided. Product deadline implementation is also a
  separate gap above.
- T-TLS: real HTTPS trust/hostname/revocation and network ACL. PKI/deployment owner
  supplies reviewed inputs; Dashboard validates from its worker network.
- Current intended PostgreSQL deployment, split-role grants, OS/systemd/load,
  crash/power-loss qualification, Windows/NXLog/notifications E2E and 24h/72h
  endurance were not executed by this rebuild.
- Dashboard's catalog audit deliberately reports all 11 transport entries as
  NOT_RUN by the central runner. The product separately records nine actual local
  Flask results; neither is live transport qualification.

## Not included / not authorized

No optional lane enablement, Phase B writer, production registry edits, deployed
credential creation, real outbound provider calls or Git synchronization.
Existing general application regression debt is not repaired or hidden here.
