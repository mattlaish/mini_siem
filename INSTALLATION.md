# mini-SIEM Installation Guide

## Recommended Linux production installation

The supported Linux production deployment uses `install-services.sh` and two systemd services.

### Service identities

`install-services.sh` creates and manages these service identities automatically:

| Component | Linux identity | Purpose |
|---|---|---|
| `mini-siem-listener` | `root:minisiem` | Receives syslog on privileged TCP/UDP port 514. |
| `mini-siem-dashboard` | `siem:minisiem` | Runs the Waitress dashboard and API pollers without an interactive login account. |

The installer creates the dedicated service account with the following contract:

```text
user:          siem
primary group: minisiem
home:          /var/lib/mini-siem
shell:         /usr/sbin/nologin (or the platform-equivalent non-login shell)
account type:  system account
```

You do **not** need to create `siem` manually and you should not substitute your personal login account. The script refuses to use UID 0 for `siem`, ensures the account has a non-login shell, and sets its primary group to `minisiem`.

The shared `minisiem` group exists so the privileged listener and unprivileged dashboard can safely access the same SQLite database, including its WAL/SHM files, while keeping the dashboard process non-root.

## 1. Place the project

Recommended location:

```bash
sudo mkdir -p /opt/mini_siem
sudo cp -a <mini-siem-source>/. /opt/mini_siem/
cd /opt/mini_siem
```

Do not copy or replace another repository's `.git/` directory as part of an application upgrade.

## 2. Create the Python environment

```bash
cd /opt/mini_siem
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

`install-services.sh` prefers `/opt/mini_siem/.venv/bin/python3` when it exists.

## 3. Install both systemd services

Run as root through `sudo`:

```bash
cd /opt/mini_siem
sudo ./install-services.sh
```

The installer will, as needed:

1. create the system group `minisiem`;
2. create the non-login system user `siem`;
3. use `/var/lib/mini-siem` as the service account home;
4. prepare permissions required for SQLite/WAL and backups;
5. verify that `siem` can execute the selected Python interpreter and import Flask/Waitress;
6. install/update `mini-siem-listener.service` and `mini-siem-dashboard.service`;
7. run the listener as `root:minisiem` and dashboard as `siem:minisiem`;
8. reload systemd and start/enable the services.

The listener remains root specifically because port 514 is privileged. Do not infer from this that the dashboard should also run as root.

## 4. Verify the installation

```bash
getent passwd siem
id siem
getent group minisiem
sudo systemctl --no-pager -l status mini-siem-listener
sudo systemctl --no-pager -l status mini-siem-dashboard
sudo ss -lntup | grep -E ':514|:8080'
ps -eo user,group,pid,cmd | grep -E '[l]istener.py|[d]ashboard.py'
```

Expected process ownership:

```text
listener.py   root:minisiem
dashboard.py  siem:minisiem
```

Expected `siem` properties include a non-login shell such as `/usr/sbin/nologin` or `/bin/false`.

## 5. Logs and troubleshooting

```bash
sudo journalctl -u mini-siem-listener -n 100 --no-pager
sudo journalctl -u mini-siem-dashboard -n 100 --no-pager
```

If the dashboard fails with SQLite read-only/WAL errors, do not solve it by making the database world-writable. Re-run `install-services.sh` so the expected `siem:minisiem` / shared-group permissions are restored, then inspect ownership and directory permissions.

On SELinux-enforcing CentOS/RHEL systems, a project copied from a home directory can retain an inappropriate `user_home_t` label. The installer attempts a safe `restorecon` repair for `/opt`; SELinux should not be disabled as a workaround.

## 6. Upgrades

For an existing installation:

1. keep the existing `.git/` metadata if this is a Git checkout;
2. stop the services before replacing application files when doing a manual upgrade;
3. preserve configuration and the complete cleanly-closed SQLite `siem.db` database;
4. replace/merge application files, not `.git/`;
5. re-run `sudo ./install-services.sh` so service definitions, service-account checks, permissions, and runtime paths are reconciled;
6. verify both service identities and health after the upgrade.

For detailed SQLite migration notes and other operating details, see `README.md`.

## 7. Uninstall behavior

When the installer is used to remove the systemd services, the service account/group and application data are intentionally not assumed disposable. Review the script's uninstall output and remove `siem`, `minisiem`, databases, or backups manually only when you are certain they are no longer required.
