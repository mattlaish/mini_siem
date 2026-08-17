# mini-SIEM

A small self-contained SIEM: a syslog receiver on port 514 (UDP + TCP),
a parser for RFC3164 and RFC5424 formats, SQLite storage, a
correlation/alerting rule engine, and a web dashboard.

```
mini_siem/
  listener.py     syslog receiver + parser + storage + rule engine hookup
  rules.py        correlation rules (brute force, denies burst, severity)
  dashboard.py    Flask web UI (log search + alert feed)
  templates/
    index.html
  requirements.txt
```

## 1. Install dependencies

```bash
pip install -r requirements.txt
```

The listener itself has zero third-party dependencies (pure standard
library — socket, sqlite3, re). Flask is only needed for the dashboard.

## 1b. Choose a database backend (do this before going live)

The SIEM can store everything in either backend — pick one up front:

- **SQLite** (default) — local, zero setup, one file. Great for a
  handful to a few dozen devices. Nothing to install or run.
- **PostgreSQL** — external server; real concurrent writes, scales well
  past SQLite's single-writer ceiling. Needs a reachable Postgres and
  the driver: `pip install psycopg2-binary`.

Run the interactive chooser:

```bash
python3 configure-db.py
```

It writes `db-config.json`, and for Postgres it tests the connection and
creates the tables so you know it works before starting. You can also
just edit `db-config.json` by hand:

```json
{
  "backend": "postgres",
  "sqlite":   { "path": "siem.db" },
  "postgres": { "host": "db.internal", "port": 5432,
                "dbname": "minisiem", "user": "minisiem", "password": "secret" }
}
```

All components (`siem.py`, `listener.py`, `dashboard.py`) read
`db-config.json` automatically. Switching backends points the SIEM at a
different store — it does **not** copy existing rows between them, which
is why the choice is best made before you start collecting. If you skip
this entirely, it defaults to SQLite at `siem.db` and everything just
works.

Note: SQLite remains the tested-by-default path in this build. The
PostgreSQL path is implemented through the same abstraction and verified
by construction; test it against your Postgres with `configure-db.py`
(which runs a real connect + table create) before relying on it.

## 1c. Authentication (login on the dashboard)

The dashboard now requires a login. Three methods, set in
`auth-config.json`, each independently enabled:

- **Local** (default, on) — username/password hashed in the DB. On
  first run it seeds **admin / admin** and *forces a password change*
  before anything else can be used. No extra packages needed.
- **OAuth / OIDC** — Google, Azure AD/Entra, Okta, Auth0, Keycloak, or
  any provider with a discovery URL. Needs `pip install authlib`.
- **SAML 2.0** — Okta, Azure AD, ADFS, etc. Needs
  `pip install python3-saml` plus system libs `xmlsec1`/`libxml2`.

First-run login:
1. Start the dashboard, open it — you'll get the login page.
2. Sign in with **admin / admin**.
3. You're immediately required to set a new password (min 8 chars, and
   it won't let you keep the default). After that the default is dead.

Enabling SSO — edit `auth-config.json`:

```json
{
  "local_auth": { "enabled": true },
  "oauth": {
    "enabled": true, "provider_name": "Okta",
    "discovery_url": "https://YOUR-DOMAIN/.well-known/openid-configuration",
    "client_id": "...", "client_secret": "...",
    "scopes": "openid email profile"
  },
  "saml": {
    "enabled": true,
    "sp_entity_id": "mini-siem",
    "sp_acs_url": "https://your-siem:8080/auth/saml/acs",
    "idp_entity_id": "...", "idp_sso_url": "...",
    "idp_x509cert": "MIIC...(IdP signing cert, no PEM header)"
  }
}
```

- OAuth redirect/callback URL to register at your IdP:
  `https://your-siem:8080/auth/oauth/callback`
- SAML SP metadata is served at `/auth/saml/metadata` once enabled; ACS
  is `/auth/saml/acs`. You can leave local auth on alongside SSO (handy
  for a break-glass admin) or turn it off once SSO works.

Security notes:
- Passwords are hashed (werkzeug pbkdf2); the session cookie is signed
  with a secret auto-generated and stored once in the DB. **Serve over
  HTTPS in production** (put nginx/Caddy with TLS in front, or a reverse
  proxy) so the session cookie can't be sniffed — the login is only as
  safe as the transport under it.
- State-changing dashboard requests require a per-session CSRF token. In
  production, also pin the public dashboard origin (the URL users see in
  their browser):
  ```bash
  export MINISIEM_ALLOWED_ORIGIN=https://siem.example.com
  ```
  Multiple public origins can be comma-separated in
  `MINISIEM_ALLOWED_ORIGINS`. Values must be exact origins (scheme, host, and
  non-default port when applicable), with no path. API-key log ingestion and
  the SAML assertion-consumer endpoint retain their own authentication and
  are intentionally exempt from browser CSRF validation.
- OAuth and SAML are implemented with established libraries (Authlib,
  python3-saml), not hand-rolled, because incorrect assertion/signature
  validation is a severe auth-bypass class. **They are verified by
  construction but were not tested against a live IdP in this build —
  test them against yours before relying on them.** Local auth is
  tested end-to-end.

## 2. Run the listener

### The "database is read-only" / having to chmod siem.db / "can't overwrite files, have to delete them every update"

If you see a read-only database error, keep having to `chmod`
`siem.db`, **or find you can't overwrite the code files on update and
have to delete them first**, the cause is the same: **file ownership
from running as root**. Binding port 514 needs elevation, so if you
first ran the listener with `sudo`, files got created owned by `root`.
When your normal user later tries to write the DB, or `cp` a new
`dashboard.py` over the old root-owned one, it's refused — deleting
works (that depends on *directory* permissions, which you have) but
overwriting doesn't (that depends on *file* ownership, which is root's).
That's why delete-then-copy works but replace doesn't. `chmod` loosens
permission bits but the ownership mismatch remains, so it recurs.

The clean fixes, best first:
1. **Run both processes as the same user.** If you use the systemd
   service (`install-service.sh`), it runs everything as one user, so
   this doesn't happen. Prefer that over launching pieces by hand with
   mixed `sudo`.
2. **Fix ownership once** if it already happened:
   ```bash
   sudo chown youruser:youruser siem.db
   ```
   (run as the user that will own the SIEM going forward)
3. **Avoid needing root at all** for port 514 using the `setcap` or
   port-redirect options below — then nothing runs as root and the DB
   stays owned by your normal user.

The point is ownership, not permission bits — `chown` once (or run as
one consistent user) and the read-only errors stop for good.


Port 514 is a **privileged port** on Linux/macOS — binding to it
requires elevated permission. Pick one:

**Option A — run as root (simplest, fine for testing):**
```bash
sudo python3 listener.py --db siem.db
```

**Option B — grant the Python binary permission to bind low ports, without running as root (Linux):**
```bash
sudo setcap 'cap_net_bind_service=+ep' $(readlink -f $(which python3))
python3 listener.py --db siem.db
```

*What that command actually does, piece by piece:*
- `setcap` — "set capability." Linux **capabilities** grant one specific
  root-like power to a program instead of full root — like handing over a
  single key rather than the master key.
- `cap_net_bind_service` — the only power being granted: "may bind
  low-numbered (privileged) network ports" (anything under 1024, e.g.
  syslog's 514). Nothing else — not file access, not process control.
- `=+ep` — the syntax for "turn this capability on" (effective + permitted).
- `$(which python3)` — finds where `python3` lives (e.g. `/usr/bin/python3`).
- `$(readlink -f ...)` — `python3` is usually a symlink to the real binary
  (e.g. `python3.12`); capabilities must be set on the real file, so this
  follows the link to it.

Put together: *"grant the real python3 binary the single ability to bind
low ports, and nothing else."* After running it, start the listener as your
normal user (no `sudo`) and it binds 514 fine. Because nothing runs as root,
no root-owned files get created — which also **fixes the "read-only
database" errors and the "can't overwrite files, have to delete them every
update" problem**, both of which come from root-owned files.

Caveat: this grants the capability to that Python interpreter for *any*
script it runs, system-wide — fine on a dedicated SIEM box, less ideal on a
shared one. To scope it to just mini-SIEM instead, use the systemd service
(`install-services.sh`), which sets the capability on that one service only.
To undo the grant later: `sudo setcap -r $(readlink -f $(which python3))`.

**Option C — bind an unprivileged port and forward 514 to it (Linux, iptables):**
```bash
python3 listener.py --port 5514 --db siem.db
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 5514
sudo iptables -t nat -A PREROUTING -p tcp --dport 514 -j REDIRECT --to-port 5514
```

**Option D — just use a high port** if you control the devices sending
logs and can point them at, say, 5514 instead of 514:
```bash
python3 listener.py --port 5514 --db siem.db
```

Full options:
```bash
python3 listener.py --host 0.0.0.0 --port 514 --protocol both --db siem.db
```
`--protocol` accepts `udp`, `tcp`, or `both` (default). Most network
gear (routers, firewalls, switches) sends syslog over UDP; some
security appliances and Linux boxes running rsyslog/syslog-ng can be
configured to send TCP for reliable delivery.

## 3. Point a device at it

- **rsyslog / syslog-ng (Linux)**: add a forwarding rule, e.g. in
  `/etc/rsyslog.d/50-forward.conf`:
  ```
  *.* @@your-siem-host:514      # TCP
  *.* @your-siem-host:514       # UDP
  ```
  then `sudo systemctl restart rsyslog`.
- **Network devices (firewalls, switches, routers)**: set the "syslog
  server" / "remote logging" address to your SIEM host's IP, port 514.
- **Test manually** with `logger`:
  ```bash
  logger -n your-siem-host -P 514 -d "test message from logger"
  ```

## 4. Run the dashboard

```bash
python3 dashboard.py --db siem.db --host 127.0.0.1 --port 8080
```
Then open `http://127.0.0.1:8080`. It polls the same SQLite file the
listener writes to, refreshing every 5 seconds. It's read-only and can
run on a different machine than the listener as long as it can reach
the `siem.db` file (e.g. on shared storage), or you point `--db` at a
copy/replica.

## 5. On-demand correlation & playbooks (/correlate)

**14 playbooks** across credential attacks, privilege abuse, malware,
network attacks, and tampering — including privilege escalation chains,
account-lockout storms (password spraying), AV/malware detections,
service-failure bursts, log-tampering indicators, and probe-then-allowed
firewall patterns.

**Playbook reports:** run every playbook over a 1/7/30/90-day window and
save the result as a report (viewable + downloadable JSON), on demand or
scheduled **weekly/monthly** — the scheduler runs inside the SIEM
process, no cron needed. Findings include the matched groups and each
playbook's response steps.


The dashboard has a second page at `http://127.0.0.1:8080/correlate`
for retrospective correlation over stored events — unlike `rules.py`,
which evaluates live as events arrive, these run whenever you ask.

**Four correlation types** (usable ad-hoc from the form):
- `threshold` — N+ events matching a regex from the same key in a window
- `sequence` — N+ "pattern A" events followed by a "pattern B" event
  from the same key within a max gap (brute force → success)
- `fanout` — one key touching many distinct values of another field
  (one IP hitting many hosts = scan/lateral movement)
- `first_seen` — keys in the recent window never seen in the baseline
  period before it (brand-new source IPs)

Keys can be `source_ip`, `hostname`, `app_name`, or `user` (extracted
from sshd/Windows message text with best-effort regexes).

**Eight built-in playbooks** (`correlations.py`), each with a
description and suggested response steps shown alongside results:
brute force then success, Windows event log cleared, new
account/privileged group addition, scan fan-out, one account from many
IPs, off-hours privileged activity, never-before-seen source IPs, and
error bursts. Add your own by appending to `PLAYBOOKS` — a playbook is
just engine parameters plus documentation.

Every result row links its evidence: sample messages inline, plus a
link that opens the exact matched events in the main log view.

## 6. Ticket system connector (/setup)

Automatically create a ticket for every alert at/above a chosen severity
— covers rule alerts, `threat_intel_match` IOC hits, everything in the
alerts table. Works with any REST ticket API (Jira, ServiceNow, Zammad,
osTicket, generic webhooks): set the URL, auth headers (write-only,
never echoed back), and a JSON body template with placeholders
(`{{rule_name}}`, `{{severity}}`, `{{description}}`, `{{source_ip}}`,
`{{ai_analysis}}`, ...). A background dispatcher sends each qualifying
alert once, records the returned ticket key on the alert, retries on
failure, and there's a "Send test ticket" button. Note: this makes
outbound HTTP calls from the SIEM to your ticket API.

## 6b. Message normalization (log search)

Click any log row to extract fields from its message: `key=value` and
`key: value` pairs are parsed automatically, and you can save custom
regex patterns (with named groups) for formats that don't use
key=value — e.g. `Failed password for (?P<user>\S+) from
(?P<src>[\d.]+)`. Patterns are validated on save and applied to any
message you expand.

**Extracted columns:** enter field names (comma-separated, up to 8) in
the normalization settings and each becomes a real column to the right
of Message — with a per-column filter box (substring, case-insensitive)
and click-to-sort headers (numeric-aware; missing values sort last).
Extracted fields are **materialized at ingest** into an indexed
`log_fields` table (same database — no second DB needed), so filtering
and sorting by extracted fields searches your ENTIRE history via
indexed lookups, with no scan cap. Requirements: a little extra disk
(one small row per field per log) and one habit — after adding or
changing patterns, click **Re-index existing logs** once so older logs
gain the new fields (new logs pick patterns up automatically within
seconds). Exports include the columns as `x_<name>` and honor the same
filters. SQLite now runs in WAL journal mode for much higher ingest
throughput (~4,500 ev/s with indexing in testing); you'll see
`siem.db-wal`/`siem.db-shm` files beside the DB — that's normal. Double-clicking an **alert** opens its related logs
in the log search view.

### How normalization works — the three layers

There are three distinct stages, each configured (or not) in a different place. Knowing which is which saves confusion:

**1. Field extraction (automatic, not configured per source).** Every incoming event has *all* its fields pulled into the searchable `log_fields` table:
- **JSON events (poller/API, e.g. Sophos):** every top-level JSON key becomes a field; a nested `source_info.ip` is surfaced as `endpoint_ip`.
- **key=value messages (e.g. Fortigate):** every `key=value` token in the message becomes a field.
- **Custom patterns:** admin-defined regex (named groups) add extra fields — saved from the log-search expand panel.

This layer is exhaustive and universal — it grabs everything, so any field is searchable even if it isn't promoted to a column. There's nothing to configure; it just runs.

**2. Built-in parsing (fixed, in code — not editable).** A few source-specific behaviors are hardcoded:
- **Fortigate (CEF/key=value):** `src=` fills the Net-source column (`source_ip`); `dst=` fills Destination. Note `FTNTFGTlevel` is Fortigate's *own* severity field — it is not the same as a mini-SIEM dashboard alert.
- **Windows / NXLog:** `EventID` maps to severity via a built-in table (e.g. 4625 = failed logon, 1102 = audit log cleared). The shipper reports facts; the SIEM assigns severity.
- **All sources:** timestamps are normalized to ISO-8601; `peer_ip` records the true network sender.

**3. Configured normalization (two editable tabs under /setup):**
- **Source field mapping** — per-source profiles that map a few chosen fields into the base columns (Host, Message, Severity, Timestamp). E.g. for Sophos, `location` → Host.
- **Search field aliases** — defines which field names count as the same *concept* for search and correlation. E.g. treat both Fortigate's `src` and Sophos's `endpoint_ip` as "source", so one Source search finds a machine regardless of which source reported it. This resolves at query time, so edits apply to all historical data immediately with no reindex. It's also what the correlation playbooks use to group events by identity across sources.

To see what fields actually exist in your data right now (e.g. to fill in an alias correctly), expand any log row in Log Search — every field is listed with its exact name and value.

## 6c. External IOC feeds (/threatintel)

Besides pasting, you can point the SIEM at a plain-text feed URL
(abuse.ch Feodo Tracker, URLhaus, Spamhaus DROP, or your own list) and
it downloads + imports the indicators — on demand ("Fetch now") or
auto-refreshed every 6h/daily/weekly. Duplicates are skipped on
re-fetch, and per-feed status shows when it last ran and what it added.
Note: feed fetching makes outbound HTTP requests from the SIEM.

## 6d. Audit trail (/audit)

Every administrative action in the SIEM itself is recorded server-side:
logins (successes AND failures, with the attempted username), logouts,
password changes, user creation/deletion, IOC and feed changes,
forwarder/AI/ticket configuration changes, and report runs — each with
the acting user and their client IP. Filter by user, action, or free
text. Secrets never enter the trail: config changes record WHICH keys
changed (e.g. "ai_api_key (updated)"), never the values.

## 6e. Database integrity & backups

Since the data lives in one SQLite file, it's worth monitoring and
backing up. Three pieces:

**On the Health page** — a "Database integrity" section shows a live
status (quick check on load), a **Check now** button (runs SQLite's full
`PRAGMA integrity_check`), a **Backup now** button (WAL-safe online
backup into `backups/`, then verifies the copy), and the DB/WAL file
sizes.

**`db-maintenance.sh`** — a standalone script for cron. Each run makes a
WAL-safe online backup, runs a full integrity check on the *copy*,
rotates to the newest N backups, and on failure shouts via stderr,
`logger`, optional email, and (optionally) a syslog line to the SIEM
itself so DB trouble shows up as an alert in your own dashboard. It does
NOT need the dashboard running and is safe while the SIEM is live.

```bash
# daily 03:00, keep 14 days, email on failure:
0 3 * * * KEEP=14 ALERT_EMAIL=you@example.com \
  /home/matt/siem123/mini_siem/db-maintenance.sh >> ~/siem-maint.log 2>&1
```
Override with env vars: `DB`, `BACKUP_DIR`, `KEEP`, `ALERT_EMAIL`,
`SIEM_SYSLOG` (e.g. `127.0.0.1:514`).

**Why online backup, never `cp`:** copying `siem.db` without its
`-wal`/`-shm` companions (or while it's being written) is the most
common way to corrupt a WAL database — likely what happened if you ever
saw `database disk image is malformed`. The `.backup` method and this
script avoid that entirely. Recovery if it does happen: restore the
newest verified backup, or `sqlite3 siem.db ".recover" | sqlite3 new.db`.

## 6f. Agents

**Linux** (`linux_agent/`) — ships journald + arbitrary log files to the SIEM
over UDP/TCP syslog, with journal-cursor resume, file-offset persistence,
rotation/truncation detection, and a heartbeat that feeds the "Silent
sources" card. Installs as a hardened, non-root systemd service:
`sudo ./install-linux-agent.sh --siem-host <SIEM-IP>`. Executed and tested
end-to-end (see linux_agent/README.md).

**Windows** (`windows_agent/`) — PowerShell agent + scheduled-task installer.
Static-checked only; never executed (no PowerShell in the build environment).

If a host already runs rsyslog, a one-line forward (`*.*  @siem:514`) may be
all you need — the agents are for journald cursors, file tailing, and
heartbeats.

## 7. Syslog forwarding (/setup)

The listener can relay every received message — the **original raw
syslog text, exactly as it arrived** — to one or more downstream
syslog receivers, in addition to storing it locally. Configure it at
`http://127.0.0.1:8080/setup`.

- **Hot-reload**: forwarder config lives in the shared SQLite DB
  (`forwarders` table). The listener re-reads it every ~5 seconds, so
  adding, editing, disabling, or deleting a destination takes effect
  without restarting anything.
- **Per-destination filters**: optionally forward only events at or
  above a minimum syslog severity, and/or only messages matching a
  regex. Blank filters forward everything. Events whose severity could
  not be parsed are treated as informational for filtering purposes.
- **Protocols**: UDP (fire-and-forget, standard syslog behavior) or
  TCP (newline framing, automatic reconnect; a failed send records
  `last_error` and drops that message — there is no buffering/replay).
- **Loop protection**: destinations pointing at the listener's own
  address and port are automatically skipped. Indirect loops
  (A→B→A) are *not* detected — don't build them.
- **Status**: the setup page shows per-destination forwarded counts
  (flushed by the listener every ~10s), last forward time, and last
  error, plus a Test button that sends one test message from the
  dashboard process.

Note the forwarded counters are updated by the *listener* process; if
only the dashboard is running, forwarders can be configured and tested
but nothing is relayed until the listener is up.

## 7. Alerting rules (rules.py)

Ships with:
- **ssh_bruteforce** — 5+ "failed password / auth failure / invalid
  user" events from the same IP within 60s → critical alert
- **firewall_deny_burst** — 20+ deny/block/drop events from the same
  IP within 60s → warning alert
- **repeated_login_failures** — 8+ generic login/access failures from
  the same IP within 120s → warning alert
- **high_severity_event** — any single log at emergency/alert/critical
  syslog severity → immediate critical alert

Add your own by subclassing `Rule` (or reusing `ThresholdRule`) in
`rules.py` and appending it to `RuleEngine.rules`.

## 8. AI SOC analyst (/ai)

A fourth page connects the SIEM to a **local** LLM to speed up triage.
It talks to any OpenAI-compatible `/chat/completions` endpoint —
Ollama, LM Studio, llama.cpp, or vLLM — so nothing leaves your network.

Setup:
1. Install a runtime and pull a model, e.g. with Ollama:
   `ollama pull qwen2.5:7b` (a 7B-class model is a fine starting point;
   larger = better reasoning, slower).
2. Open `/ai`, expand **LLM connection**, set the endpoint and model:
   - Ollama: `http://localhost:11434/v1`, model `qwen2.5:7b`
   - LM Studio: `http://localhost:1234/v1`, model as shown in its UI
3. Click **Test connection**. Save.

What it does:
- **Automatic triage (proactive)** — when enabled, every new alert is
  sent to the model *as it fires* and its analysis is attached to the
  alert automatically. Runs in a background worker, off the ingest path,
  so it never slows log collection: the listener raises the alert
  instantly (marked `pending`) and the worker drains pending alerts to
  the LLM one at a time. If the LLM is off or unreachable, alerts wait
  and get analyzed once it's back (failed calls retry, then mark
  `error`). Toggle it and set a minimum severity on the AI page. The
  main alert feed shows a "✓ analysis" button on triaged alerts.
- **Triage an alert (manual)** — pick a recent alert; the server gathers the
  triggering events plus that source's history and asks the model for a
  structured assessment (summary, true/false-positive call with
  confidence, severity view, recommended actions, what to check next).
- **Ask about your logs** — a chat box; the server retrieves relevant
  events by keyword and passes them as evidence for the model to answer
  over.

Security model (why it's built this way):
- **Read-only.** The model never runs queries. The server assembles a
  bounded context (capped event count and message length) and passes it
  in. This removes the prompt-injection risk of letting a model act on
  attacker-controlled log text — and the system prompts explicitly tell
  the model to treat log contents as data, not instructions.
- **Local.** With a local runtime, log data never leaves your
  infrastructure. (If you point it at a remote OpenAI-compatible
  service instead, your log context would be sent there — so keep it
  local for sensitive environments.)
- The AI's output is assistive, not authoritative; the page says so and
  every answer ends with a verify-before-acting reminder.
- The LLM API key (if any) is stored in the DB and never echoed back to
  the browser.

Config lives in the `app_config` table and is edited entirely from the
page — no restart needed. AI calls are made by the **dashboard**
process, so the LLM runtime needs to be reachable from wherever the
dashboard runs.

## 9. Threat intelligence / IOC matching (/threatintel)

Match every incoming log against your own indicator lists, live at
ingest. Supported indicator types: **IP, domain, URL, file hash**
(MD5/SHA1/SHA256 — auto-detected).

How matching works:
- IPs are checked against the event's source IP (including the real
  source lifted from `srcip=`/`Source IP:` fields by enrichment), the
  host field, and any IPs appearing in the message text.
- Domains/URLs are matched as substrings of the message; hashes are
  extracted from message text and looked up exactly.
- A hit records on the Threat Intel page **and raises a
  `threat_intel_match` alert** (with the severity you set per
  indicator), so it shows on the main dashboard and gets auto-triaged
  by the AI Analyst if that's enabled.

Managing indicators:
- **Add one** — value + optional type (auto-detected), threat name and
  alert severity.
- **Paste a feed** — one indicator per line, `#` comments, or CSV
  `value,type,threat` per line. Works with copy-pastes from abuse.ch
  (Feodo Tracker, URLhaus), Spamhaus DROP, or your own lists. Give the
  feed a name; re-importing skips duplicates, and "Delete this feed"
  removes the old set when you want to load an updated copy.
- Enable/disable or delete indicators individually. Changes take effect
  within ~5 seconds (the matcher hot-reloads; no restart).

Honest scope note: this matches indicators **you provide** — the SIEM
does not (yet) auto-download feeds from the internet on a schedule.
Pasting a feed weekly takes a minute; scheduled feed pulls are a natural
next step if you want them.

## 10. Easiest way to run: one command / install as a service

Instead of running listener.py and dashboard.py separately, use the
combined entry point:

```bash
sudo python3 siem.py
```

That starts the syslog listener (UDP+TCP 514) and the dashboard
(127.0.0.1:8080) together in one process. Same flags as the individual
scripts: `--port`, `--protocol`, `--db`, `--dashboard-host`,
`--dashboard-port`, `--no-dashboard`.

To make it fully hands-off — start at boot, restart on failure —
install it as a systemd service:

```bash
cd /opt/mini_siem        # or wherever you keep the folder permanently
sudo ./install-service.sh
```

Then manage it like any service:

```bash
systemctl status mini-siem
journalctl -u mini-siem -f          # live event/alert/forwarder output
sudo systemctl restart mini-siem    # after updating code
sudo ./install-service.sh uninstall # remove the service (keeps files + DB)
```

The installer writes the unit file pointing at the folder you run it
from, checks Flask is importable first, and stores the database as
`siem.db` in that same folder. Note the combined process runs as root
(needed for port 514) — keep the dashboard on 127.0.0.1 and use an SSH
tunnel, or use the non-root options in section 2 and edit `User=` in
the unit.

## 11. Manual/legacy: separate processes (optional)

Example systemd unit for the listener (`/etc/systemd/system/mini-siem-listener.service`):
```ini
[Unit]
Description=mini-SIEM syslog listener
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/mini_siem/listener.py --db /opt/mini_siem/siem.db
Restart=on-failure
User=root
WorkingDirectory=/opt/mini_siem

[Install]
WantedBy=multi-user.target
```
(Use `User=root` only if binding port 514 directly; otherwise apply
Option B/C/D above and drop to an unprivileged user.)

## Notes and limitations

- SQLite is fine for low/medium volume (a handful of devices, a few
  hundred events/minute). For high-volume production use, swap
  `Storage` in `listener.py` for Postgres/ClickHouse/Elasticsearch —
  the insert interface is small and easy to re-implement.
- The rule engine's state (sliding windows) lives in memory and resets
  if the listener restarts. For durability across restarts, back the
  counters with a small persistent store.
- TCP framing here assumes newline-delimited messages (the common
  case). Some devices use RFC6587 octet-counted framing instead; if
  you hit one, the TCP handler in `listener.py` is the place to add it.
- This is a lightweight/reference implementation, not a hardened
  Internet-facing service — run it inside your trusted network
  perimeter, not exposed directly to the internet.
