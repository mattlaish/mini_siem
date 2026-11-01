# Fresh rebuild validation — 2026-10-22

Scope: Python 3.12 / Windows, disposable synthetic SQLite data, actual mini-SIEM
routes and existing Dashboard offline consumer. Source is the current Projects
tree; old October 4 execution logs were not substituted as new evidence.

| Check | Observed result / evidence |
|---|---|
| Focused current-source regression | 123 PASS; `test-logs/focused-regression.stdout.txt` and XML; includes detection hardening, operator UI, DB/auth, connector and eight package-safety tests |
| Full Windows-compatible suite | 339 PASS / 47 FAIL / 3 SKIP; same 47 failure identities as the October 18 report, no new failures; `test-logs/full-regression.json` and XML |
| Dashboard fixture replay | PASS: 21 pages, 26 records, 6 decoder negatives; `test-logs/dashboard-execute.stdout.txt` |
| Stage-aware negative catalog | 14 PASS / 0 FAIL / 0 BLOCKED; `test-logs/dashboard-catalog-audit.stdout.txt` |
| Positive late historical revision | PASS: accepted 2 then 1, current stays 2; `test-logs/P-SYNC-001.json` |
| Product transport | 9 local PASS / 2 NOT_RUN, each with independent request and actual evidence reference |
| Central transport execution | 11 NOT_RUN; catalog receipt is not transport execution |
| Source identity | Ten repo-relative inputs; final archive audit must report 10 MATCH, no missing/different files |
| Final content/checksum/CRC/secret review | See final archive audit and SHA-256 sidecar alongside ZIP |

Local transport results: T-401, T-403, T-409, T-429, T-503, T-MUTATION,
T-REDIRECT, T-CONTENT-TYPE and T-OVERSIZE are exercised through Flask. The content
type case checks the server's safe response, not a claim that a live client was
fed and rejected every invalid media type. T-REDIRECT checks no redirect on an
unknown path; it is not a live TLS redirect-follower test. T-409 evicts a synthetic
snapshot; T-503 constrains snapshot capacity; T-OVERSIZE seeds an invalidly long
synthetic hostname. No claims are prefilled for timeout or TLS.

`test-logs/offline-checks.json` records precise commands, exit status, consumer
source hashes, binding/bundle hashes and actual replay outcomes. Initial broader
checks exposed a missing local tzdata path and sandbox temporary-directory ACL
issues; reruns use the already-installed test dependencies and an isolated
temporary directory. The full runner explicitly uses UTF-8, matching the earlier
validation environment. The truth gate applies its existing, explicit example
policy to the delivered source mirror without skipping delivered-code checks;
three new tests ensure unmarked or other placeholder code still fails.
No application workaround or permission relaxation was made. POSIX pwd/systemd
collection is excluded on Windows, as in the comparison baseline. The complete
suite remains red; existing search/performance/UI/permission debt is not repaired.

These tests do not establish all O-01..O-08 requirements. See `open-gaps.md` for
missing product implementations as distinct from missing deployment environment.
Full R3/G1 and live G3 must not be promoted based on the offline counts.
