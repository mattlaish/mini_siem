# P3 Linux / systemd Host Qualification

Status: `IMPLEMENTED_TESTING_DEFERRED`

P3 runtime hardening is implemented in source. Production qualification must be
performed on a real systemd host; a container without systemd PID 1 is
`BLOCKED_ENVIRONMENT`, not PASS and not a product failure.

## Security model

The standard service identities are non-login system accounts:

- `siem-listener` / group `minisiem-listener` — syslog listener;
- `siem` / group `minisiem-dashboard` — dashboard/API;
- `siem-maintenance` / group `minisiem-maintenance` — bounded PostgreSQL partition maintenance;
- `minisiem` — shared **code/read-state** group only, never a PostgreSQL component-secret group.

Each service is also a member of `minisiem` so it can read the deployed source.
PostgreSQL credential files use the component-specific groups above. This prevents
the listener, dashboard, and maintenance identities from reading one another's
PostgreSQL passwords.

For PostgreSQL deployments the application source root is runtime-immutable:
service users must not be able to create, replace, or delete files there. Archive
state, when enabled, must use an absolute path outside the source tree such as
`/var/lib/mini-siem/archive`. SQLite retains the historical source-adjacent DB/WAL
layout and is therefore an explicit compatibility exception.

## Live qualification runner

Run after installation/upgrade on the target host:

```bash
sudo ./.venv/bin/python tools/systemd_host_qualification.py \
  --project-root /opt/mini_siem \
  --output /var/lib/mini-siem/p3-systemd-current.json
```

On SELinux-enforcing RHEL-family qualification targets add:

```bash
  --require-selinux-enforcing
```

The runner is read-only and validates actual runtime state, including:

- non-root, non-login service identities;
- enabled/active systemd services and PostgreSQL partition timer;
- live systemd sandbox properties (`NoNewPrivileges`, capability bounds,
  `ProtectSystem`, kernel/control-group protections, restricted address families);
- actual `/proc/<pid>/status` effective and ambient capabilities;
- listener bind capability limited to `CAP_NET_BIND_SERVICE`;
- empty capability allowance for dashboard/maintenance;
- PostgreSQL source-tree immutability to all runtime identities;
- component credential readability and cross-component denial;
- expected syslog/dashboard listening sockets;
- `systemd-analyze verify` of installed units;
- SELinux source labels and relevant boot AVC denials when the tools are present.

## Reboot qualification

Before reboot:

```bash
sudo ./.venv/bin/python tools/systemd_host_qualification.py \
  --project-root /opt/mini_siem \
  --phase pre-reboot \
  --output /var/lib/mini-siem/p3-before-reboot.json
```

After reboot:

```bash
sudo ./.venv/bin/python tools/systemd_host_qualification.py \
  --project-root /opt/mini_siem \
  --phase post-reboot \
  --baseline /var/lib/mini-siem/p3-before-reboot.json \
  --output /var/lib/mini-siem/p3-after-reboot.json
```

`post-reboot` requires a changed kernel boot ID in addition to the normal live
service/security checks. Keep both JSON files as qualification evidence.

## Promotion rule

P3 remains `IMPLEMENTED_TESTING_DEFERRED` until representative target-host runs
PASS. Source/unit tests or an environment-blocked local run do not promote P3 to
`TESTED`.
