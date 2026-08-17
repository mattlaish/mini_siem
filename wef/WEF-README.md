# mini-SIEM via Windows Event Forwarding (WEF)

Collect Windows logs from many machines **without installing an agent on each
one**. The endpoints use WEF (built into Windows) to forward events to one
**collector**; the mini-SIEM Windows agent runs only on that collector and
ships everything to the SIEM as syslog.

```
200 endpoints ──WEF (native, no agent)──▶ Collector ──MiniSiemAgent──▶ mini-SIEM
   (Group Policy configures them)          (ForwardedEvents log)      (syslog)
```

Why this instead of an agent per machine: nothing custom or unsigned runs on
the endpoints, so **EDR has nothing to flag** — WEF is Microsoft's own
machinery. You maintain config in one place (Group Policy), not 200 places.

> **Your environment:** on-prem AD domain `EVANHOSP`, no Entra — so the fleet
> path is **Group Policy** (not Intune). The name suggests a clinical setting;
> see the "Hospital / regulated" notes below and treat the rollout as a
> change-controlled deployment: test OU first, then widen.

---

## Phase 1 — Prove it on ONE machine (no domain, no GPO, no second box)

Do this first, on a test machine, before touching Group Policy. One machine
plays source + collector + forwarder so you can watch events flow end to end.

1. Copy the `wef/` folder and your `windows_agent/` folder to the test box.
2. In an **elevated** PowerShell:
   ```powershell
   cd wef
   .\Setup-WEF-Test.ps1
   ```
   This starts the collector service (`wecsvc`), configures WinRM, creates the
   `mini-SIEM-Test` subscription from `Subscription.xml`, points the machine at
   itself as collector, and grants log-read access.
3. Generate an event — lock and unlock the screen (logon 4624/4634), or run a
   program if process-creation auditing is on (4688).
4. Confirm events reached the collector:
   ```powershell
   Get-WinEvent -LogName 'ForwardedEvents' -MaxEvents 5
   ```
   If you see events here, **WEF works**. If not, see Troubleshooting.
5. Point the mini-SIEM agent at the collected events and start it:
   ```powershell
   cd ..\windows_agent
   copy ..\wef\wef-agent-config.json .\agent-config.json
   # edit SiemHost to your mini-SIEM IP first
   .\MiniSiemAgent.ps1 -TestConnection
   .\MiniSiemAgent.ps1
   ```
6. Watch the mini-SIEM dashboard's **Live logs** — forwarded Windows events
   should appear, tagged with the originating machine.

Undo the test setup any time: `.\Setup-WEF-Test.ps1 -Undo`

---

## Phase 2 — Roll out to the fleet (Group Policy)

Once Phase 1 works, the ONLY thing that changes for the other 199 machines is
*how they're told to forward*: Group Policy instead of the local registry key
the test script set. The subscription and the collector stay the same.

### 2a. Stand up a real collector
- A Windows **Server** that's always on (not a desktop). One collector handles
  200 source-initiated clients comfortably; size CPU/RAM/disk for the
  `ForwardedEvents` volume and keep the mini-SIEM agent running on it.
- On the collector: `wecutil qc`, then create the subscription:
  `wecutil cs Subscription.xml` (edit `<SubscriptionId>` to e.g. `mini-SIEM`).

### 2b. Two Group Policy settings (link to a TEST OU first)
1. **Point endpoints at the collector.**
   `Computer Configuration → Policies → Administrative Templates → Windows
   Components → Event Forwarding → Configure target Subscription Manager`
   → Enabled → add:
   `Server=http://COLLECTOR.evanhosp.local:5985/wsman/SubscriptionManager/WEC,Refresh=60`
2. **Let the collector read the Security log.**
   `Computer Configuration → Policies → Windows Settings → Security Settings →
   Restricted Groups` (or a GPO preference): add **NETWORK SERVICE** to the
   local **Event Log Readers** group on the endpoints.

Optional but recommended for coverage:
3. **Enable process creation auditing** (for 4688):
   `Advanced Audit Policy → Detailed Tracking → Audit Process Creation → Success`
4. **PowerShell script block logging** (for 4104):
   `Administrative Templates → Windows Components → Windows PowerShell → Turn on
   PowerShell Script Block Logging`

### 2c. Widen the rollout
Link the GPO to a small test OU. Confirm those machines appear in
`ForwardedEvents` on the collector (`wecutil gr mini-SIEM` shows active
sources). Then widen the OU scope in stages. This staged approach is exactly
what change control in a hospital expects — never link fleet-wide on day one.

---

## What gets collected (curated, not "everything")

`Subscription.xml` deliberately collects a **high-signal subset**, not all
events. At 200 machines "collect everything" is tens of millions of events a
day — it buries your alerts and bloats `siem.db`. Included:

- **Logons/logoff/privilege:** 4624, 4625, 4634, 4647, 4648, 4672
- **Account & group changes:** 4720–4726, 4740, 4767, 4728/4732/4756 (+removals)
- **Process creation:** 4688 (needs audit policy on)
- **Tampering:** 1102 (log cleared), 4719 (audit policy changed), System 104
- **Persistence:** 4698/4702 (scheduled tasks), 7045 (service install)
- **Service health:** 7040, 7031, 7034
- **PowerShell:** 4104 (script block, if enabled)
- **Sysmon:** all, if installed (harmless if not)

To collect more later, add `<Select>` lines to the subscription and update it
with `wecutil ss`. Add deliberately — each addition is volume you store and
protect.

---

## Hospital / regulated environment notes

- **PHI in logs:** Windows events carry usernames, workstation names, and can
  incidentally include PHI. Everywhere those events land — collector,
  `siem.db`, backups — is now in scope for your safeguards. Keep collection
  curated and access-controlled.
- **Secure the collector→SIEM hop.** 200 machines of security events over
  cleartext syslog on a clinical LAN is worth tunnelling (WireGuard/stunnel/ssh
  -L) since the syslog listener has no TLS. The config uses **TCP** so a tunnel
  is straightforward.
- **Change control.** The two GPOs touch every targeted machine. Stage via a
  test OU, document, and follow your org's process.
- **Validate, don't trust blindly.** These files are correct by construction
  but were **not** tested in your environment — no Windows/AD in the build
  system. Prove Phase 1 on one machine, then a test OU, before the fleet.

---

## Troubleshooting

- **Nothing in ForwardedEvents:** on the endpoint, `Event Viewer → Applications
  and Services → Microsoft → Windows → Eventlog-ForwardingPlugin/Operational`
  shows WEF errors. Common causes: WinRM not reachable (`Test-NetConnection
  COLLECTOR -Port 5985`), collector not granted log read, clock skew.
- **Collector shows no sources:** `wecutil gr <SubscriptionId>`. Check the
  SubscriptionManager URL and that endpoints applied the GPO (`gpupdate
  /force`, then `gpresult /r`).
- **Agent sees ForwardedEvents but SIEM doesn't:** `MiniSiemAgent.ps1
  -TestConnection`; check firewall to the SIEM port and that the SIEM listener
  is up.
