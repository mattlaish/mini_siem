# Security recovery — 2026-10-27

Connector update 2026-10-28: the recovered machine reader is now integrated without
reverting these browser/outbound protections. Its own bearer boundary rejects
browser-cookie authorization; PostgreSQL deployment adds five owner-created tables
and restricted state grants. See `RECOVERY_2026-10-28.md`. No production schema,
token, role or credential changes were performed by the recovery itself.

Status: locally tested recovery merge, not production qualification. The active
source is `C:/Users/mattlai/Projects/mini_siem`. See `RECOVERY_2026-10-27.md` for
the overwritten baseline, preserved changes and missing historical deliverables.

## What changed

1. Browser sessions are checked against the current database account on each
   protected request. A signed stamp binds username, authentication source,
   account creation time and password hash. Deleted/recreated accounts and old
   cookies must sign in again; password changes invalidate other browsers on
   their next request. The browser changing its own password remains signed in.
   Database verification failures return 503, never cached administrator access.
2. Effective roles come from the database, not the cookie. Protected writes
   default to administrator-only, with explicit analyst, self-service and
   read-only-operation exceptions. Account listings require administrator access.
   New OAuth/SAML identities default to viewer; a same-name identity from a
   different authentication source is rejected. Existing database roles are not
   silently changed: review previously provisioned SSO administrators yourself.
3. Pollers, IOC feeds, ticket delivery and AI use `outbound.py`. Destination
   policy, DNS validation/pinning, certificate verification, size/time/concurrency
   limits and redirect rejection apply to the actual network connection.
4. Arbitrary extracted field names/values and account/connection names are
   escaped for their HTML contexts. Deletion controls use data attributes and
   delegated handlers instead of interpolating names into JavaScript source.
5. Upstream HTTP error bodies are withheld from operator error messages. Status
   codes and connection-test phases remain available without echoing provider
   credentials or response bodies. Successful bounded samples can contain real
   event data and remain administrator-only.

## Outbound services

Public HTTPS destinations are permitted by default; this is not a public-domain
allowlist. Non-global destinations and HTTP require an exact allowed origin:

```text
MINISIEM_OUTBOUND_ALLOWLIST=https://ticket.internal.example:8443,http://10.20.30.40:8080
```

Use comma-separated scheme/hostname/port origins only, with no credentials,
paths or wildcards. An entry is shared across these outbound integrations; keep
it as narrow as possible. Link-local, known cloud metadata, unspecified,
multicast and reserved destinations remain blocked even when listed. All DNS
answers must pass validation; the connection uses the validated literal address,
while retaining the original HTTP Host and TLS hostname/certificate checks.
Redirects and environment proxy settings are not followed.

Local AI permits localhost, 127.0.0.1 and ::1 on ports 11434/1234 by default;
other internal AI origins need the explicit list. The existing
`MINISIEM_AI_ALLOW_INSECURE_LOOPBACK_EXTERNAL=1` development option is limited to
loopback and is not a production HTTPS alternative. Localhost must actually
resolve to loopback unless its origin is explicitly allowed.

Sophos mode additionally restricts authentication to `id.sophos.com`, discovery
to `api.central.sophos.com`, and regional event calls to Sophos Central API
hosts over HTTPS port 443. OAuth token refresh, Whoami discovery, automatic
tenant headers and cursor behavior are retained. Other/custom modes still use
the shared destination policy.

Limits per response are 8 MiB for poller/general JSON, 16 MiB for feeds and
4 MiB for AI. Worker previews are separately truncated for display; a full feed
is never an unlimited download. Declared and streamed oversize bodies and
incomplete declared bodies fail. Four outbound calls can be active per process;
excess calls fail promptly. Socket IO is deadline-bounded with a watchdog;
the operating system DNS resolver can still exceed that deadline. These limits
do not provide an organization-wide quota or replace network egress controls.

## Permissions and browser behavior

Analysts retain the October 21 SOC workflows: alert updates/bulk triage, AI
analysis/chat, manual reports, IOC changes/import, fetching an already configured
feed, and display-column changes. Feed configuration, extraction-pattern changes,
reindexing, provider settings and connection tests require administrators.
Viewers cannot mutate these resources. Existing endpoint-specific restrictions
still apply; the default write guard does not weaken them.

CSRF tokens and optional exact browser-origin enforcement remain in place:
`MINISIEM_ALLOWED_ORIGIN=https://siem.example.com`. HTTPS deployments should set
`MINISIEM_COOKIE_SECURE=1`. The current compatibility CSP still permits inline
scripts: escaping is essential, and this recovery does not claim a strict CSP.

The stamp is account-bound, not a server-side per-session revocation registry.
Logging out clears the current cookie; an independently stolen valid cookie
is not centrally revoked solely by that logout. Use HTTPS, short idle limits,
password changes and controlled administrator access as appropriate.

## Deployment and preserved design

Deploy the complete matching Python/static/template set together, including the
new `outbound.py`, then restart listener and dashboard. Do not replace a single
Python file and leave old assets behind. No database schema migration, production
credential replacement or runtime privilege increase was made by this recovery.
Existing browser cookies will require sign-in again.

Trusting X-Forwarded-For remains the owner's explicit environment requirement;
control access to the trusted proxy path. Memory-only live rule windows still
reset at restart by design. Sophos OAuth refresh/cursor semantics were not
redesigned. The portable Sophos snapshot/ZIP has not been rebuilt with these
transport changes and must not be represented as the hardened application.

## Evidence and limits

Final Windows suite: 446 PASS / 47 FAIL / 3 SKIP. Failure identities are identical
to the pre-recovery baseline (363 PASS / 47 FAIL / 3 SKIP). Focused security,
workflow and preserved-feature checks: 247 PASS, with four already-recorded
Windows permission failures deselected from that focused run only. All remain
visible in the full result. Six Node runtime tests exercise actual UI code with
synthetic DOM/network stubs; they are not a real-browser certification.

Real IdP, Sophos tenant, PostgreSQL, Windows/NXLog delivery, external TLS endpoint,
Linux ownership and systemd deployment qualification were not run. No Git
operation, production database write or real provider request was performed.
