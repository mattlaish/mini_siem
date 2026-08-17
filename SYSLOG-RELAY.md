# mini-SIEM — Syslog relay (forwarding)

Relay every syslog message mini-SIEM receives onward to one or more other
collectors, **in addition to** storing and analysing it locally. mini-SIEM
acts as a syslog relay: it is a destination for your devices and a source
for whatever sits downstream.

```
devices ──syslog──▶ mini-SIEM ──┬──▶ store + rules + threat-intel + field index
                                └──▶ relay to downstream collector(s)
```

What gets relayed is the **original raw message text**, as received, before
any parsing or normalisation — not a reformatted or re-serialised version.

---

## 1. Where it lives

| Piece | File |
|---|---|
| Relay engine | `forwarder.py` (`ForwarderManager`, `_RuntimeForwarder`) |
| Called from the ingest pipeline | `listener.py` / `siem.py` (`on_message`) |
| Configuration API | `dashboard.py` (`/api/forwarders`) |
| Configuration UI | Setup page → **Syslog forwarding** |
| Stored config | `forwarders` table in `siem.db` |

---

## 2. Configuring a destination

Setup page → **Syslog forwarding** → fill the form → **Add forwarder**.

| Field | Meaning |
|---|---|
| **Name** | Label for your own reference. |
| **Host** | Downstream collector's address. |
| **Port** | Its syslog port (commonly 514). |
| **Protocol** | `udp` or `tcp`. |
| **Minimum severity** | Only relay events at or above this severity. Blank = everything. |
| **Filter pattern** | Optional regex; only messages matching it are relayed. Blank = everything. |
| **Preserve origin** | `off` / `hostname` / `sd` / `both` — see §4. |

Configuration changes take effect **without restarting** the SIEM: the
relay re-reads the `forwarders` table every 5 seconds, so adding,
editing, disabling, or deleting a destination applies within seconds and
never interrupts ingestion.

Only **administrators** can create, edit, or delete forwarders; the
endpoints are role-gated and every change is written to the audit trail.

### Configured destinations table

Below the form, each destination shows its target, protocol, filters,
origin mode, cumulative forwarded count, last forward time, and last
error (if any). Counters are flushed from memory to the database every
10 seconds, so they lag live traffic slightly.

---

## 3. Filtering

Two independent gates, both optional. A message is relayed only if it
passes both.

- **Minimum severity** — compared against the event's parsed syslog
  severity. Events whose severity could not be determined are treated as
  *informational*.
- **Filter pattern** — a case-insensitive regex evaluated against the
  **raw** message text.

Filters are per destination, so one collector can receive everything
while another receives only critical firewall events.

---

## 4. Preserving the original sender ("Preserve origin")

**The problem.** A relay hides the original device. Packets arrive at the
downstream collector from *mini-SIEM's* IP, so anything that keys on the
network source address attributes every message to the SIEM.

Because different collectors key on different things, this is a
per-destination setting with four modes:

| Mode | What it does | When to use it |
|---|---|---|
| **`off`** *(default)* | Relays the message untouched. | You want a faithful passthrough, or the downstream already gets what it needs. |
| **`hostname`** | Inserts the sender's IP into the syslog HOSTNAME field **only when the device left it empty** (`-` or absent). Never overwrites a hostname the device supplied. | Your collector indexes the syslog HOSTNAME field, and some devices don't send one. |
| **`sd`** | Attaches an RFC 5424 structured-data element `[origin ip="…"]`. Always present, always parseable. | Your collector keys on source IP, or devices send hostnames but you still need the true origin. |
| **`both`** | Applies both of the above. | **Recommended starting point when you don't know how the downstream behaves** — whichever it reads, it will find something. |

### Format-specific behaviour

- **RFC 5424** — `hostname` replaces the `-` NILVALUE in the HOSTNAME
  field. `sd` inserts `[origin ip="…"]` in the correct structured-data
  position; **existing structured data is preserved** (SD elements
  concatenate legally).
- **RFC 3164** — `hostname` inserts the IP after the timestamp when no
  hostname token is present. There is no structured-data field in this
  format, so `sd` appends `[origin ip="…"]` to the end; the original text
  stays intact.
- **Non-conformant messages** — there is no reliable structure to edit,
  so `hostname` is a no-op; `sd` appends the element.

### Which IP is used

The **true network sender** (the peer address of the connection or
datagram), carried on the event as `peer_ip`.

This matters: mini-SIEM's parser overwrites an event's `source_ip` with
any `src=` value found *inside* the message text. A firewall log reading
`src=10.9.9.9` would otherwise be attributed to 10.9.9.9 rather than to
the firewall that actually sent it. Origin preservation deliberately uses
`peer_ip`, which nothing can overwrite.

### What this is not

Source-IP **spoofing** (making relayed packets appear to come from the
original device, as `rsyslog`'s `omudpspoof` does) is not implemented. It
is the only way to preserve origin at the packet level, but it requires
raw sockets (root), works over UDP only, is commonly dropped by
anti-spoofing / uRPF filters, and makes network monitoring see traffic
claiming to be from hosts that did not send it.

---

## 5. Delivery semantics

- **UDP** — fire-and-forget. A "sent" result does not prove delivery.
- **TCP** — newline-framed, with a 3-second connect timeout and automatic
  reconnect on the next message after a failure.
- **No buffering or replay.** A failed send is dropped and recorded in
  `last_error`. If a downstream collector restarts, messages in flight
  during the outage are lost.
- **Loop protection.** A destination pointing at this listener's own port
  on localhost is refused and logged, rather than creating a forwarding
  loop.

---

## 6. Known limitations

Worth understanding before relying on this in production.

1. **Not byte-exact.** Messages are decoded to text on receipt and
   re-encoded on send, both with `errors="replace"`. Normal ASCII/UTF-8
   syslog passes through unchanged; non-UTF-8 bytes are replaced.

2. **Relaying runs inline in the ingest path.** `forward()` is called
   synchronously while processing each message, and TCP has a 3-second
   connect timeout. A slow or unreachable TCP collector can therefore
   stall ingestion. UDP does not have this problem. If you relay over TCP
   to a collector that may be down, be aware of this cost.

3. **No retry or queue.** See §5.

4. **TCP framing is newline-delimited**, not RFC 6587 octet-counted. Most
   collectors accept newline framing; some expect octet counts.

5. **Messages ingested via the HTTP API** (`/api/ingest`) are relayed
   too, but their "raw" text is the syslog line mini-SIEM *synthesises*
   from the posted JSON — not an original wire message.

6. **No TLS.** Relayed syslog is cleartext. Tunnel it (WireGuard,
   stunnel, `ssh -L`) if it crosses a network you don't control.

---

## 7. Troubleshooting

| Symptom | Where to look |
|---|---|
| Nothing arriving downstream | Check the destination is **enabled**; check `last_error` in the destinations table; confirm the severity/regex filters aren't excluding everything. |
| Counter rising but collector shows nothing | UDP is fire-and-forget — check firewall rules between the two hosts, and that the collector is listening on that port/protocol. |
| Everything attributed to the SIEM | Set **Preserve origin** to `both` (§4). |
| TCP destination intermittently missing messages | Expected on reconnect — there is no replay (§5). Consider UDP, or accept the gap. |
| Ingestion feels slow after adding a TCP forwarder | See limitation #2 — the downstream may be timing out. |
