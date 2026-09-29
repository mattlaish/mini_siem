#!/usr/bin/env python3
"""Production host acceptance for mini-SIEM systemd/SELinux hardening.

This runner validates the *live* host instead of inferring safety from unit-file
text.  It is intentionally read-only.  It records machine-readable evidence and
fails closed on required security/runtime checks.  Reboot qualification is a
2-step flow using --phase pre-reboot followed by --phase post-reboot --baseline.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "listener": "mini-siem-listener.service",
    "dashboard": "mini-siem-dashboard.service",
    "maintenance": "mini-siem-event-partitions.service",
}
TIMER = "mini-siem-event-partitions.timer"
EXPECTED_USERS = {
    "listener": "siem-listener",
    "dashboard": "siem",
    "maintenance": "siem-maintenance",
}
CAP_NET_BIND_SERVICE_BIT = 10
SYSTEMD_PROPERTIES = [
    "User", "Group", "SupplementaryGroups", "NoNewPrivileges",
    "AmbientCapabilities", "CapabilityBoundingSet", "ProtectSystem",
    "PrivateTmp", "ProtectHome", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectControlGroups", "RestrictSUIDSGID",
    "LockPersonality", "RestrictAddressFamilies", "MainPID",
    "ActiveEnterTimestampMonotonic",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)


def check(name: str, ok: bool, detail: Any = None, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "required": bool(required), "detail": detail}


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None



def systemd_runtime_available() -> tuple[bool, str]:
    if not command_exists("systemctl"):
        return False, "systemctl unavailable"
    try:
        pid1 = Path("/proc/1/comm").read_text(encoding="utf-8").strip()
    except Exception:
        pid1 = "unknown"
    runtime_dir = Path("/run/systemd/system").is_dir()
    return pid1 == "systemd" and runtime_dir, f"pid1={pid1} /run/systemd/system={runtime_dir}"

def read_backend(config_path: Path) -> tuple[str, dict[str, Any]]:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    backend = str(data.get("backend") or "").strip().lower()
    if backend not in {"sqlite", "postgres"}:
        raise RuntimeError(f"unsupported/missing backend in {config_path}: {backend!r}")
    return backend, data


def parse_systemctl_show(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value
    return out


def cap_mask_from_proc(pid: int) -> tuple[int, int]:
    eff = amb = 0
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("CapEff:"):
            eff = int(line.split()[1], 16)
        elif line.startswith("CapAmb:"):
            amb = int(line.split()[1], 16)
    return eff, amb


def active_enabled(unit: str) -> tuple[bool, dict[str, Any]]:
    active = run(["systemctl", "is-active", unit])
    enabled = run(["systemctl", "is-enabled", unit])
    return (
        active.returncode == 0 and active.stdout.strip() == "active"
        and enabled.returncode == 0 and enabled.stdout.strip() in {"enabled", "static"},
        {
            "active": active.stdout.strip() or active.stderr.strip(),
            "enabled": enabled.stdout.strip() or enabled.stderr.strip(),
        },
    )


def unit_properties(unit: str) -> dict[str, str]:
    args = ["systemctl", "show", unit]
    for prop in SYSTEMD_PROPERTIES:
        args += ["-p", prop]
    cp = run(args)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or f"systemctl show failed for {unit}")
    return parse_systemctl_show(cp.stdout)


def nonlogin_user_check(username: str) -> dict[str, Any]:
    try:
        p = pwd.getpwnam(username)
    except KeyError:
        return check(f"account:{username}", False, "missing")
    shell = p.pw_shell or ""
    return check(
        f"account:{username}",
        p.pw_uid != 0 and (shell.endswith("/nologin") or shell.endswith("/false")),
        {"uid": p.pw_uid, "gid": p.pw_gid, "shell": shell},
    )


def test_as_user(username: str, test_args: list[str]) -> tuple[bool, str]:
    if not command_exists("runuser"):
        return False, "runuser unavailable"
    cp = run(["runuser", "-u", username, "--", "test", *test_args])
    return cp.returncode == 0, cp.stderr.strip()


def credential_checks(root: Path, backend: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    config = root / "db-config.json"
    if config.exists():
        mode = stat.S_IMODE(config.stat().st_mode)
        checks.append(check("db-config-mode", mode & 0o022 == 0, oct(mode)))
    if backend != "postgres":
        return checks
    paths = {
        "listener": root / "db-listener-credentials.json",
        "dashboard": root / "db-dashboard-credentials.json",
        "maintenance": root / "db-maintenance-credentials.json",
    }
    for identity, path in paths.items():
        if not path.exists():
            checks.append(check(f"credential:{identity}:exists", False, str(path)))
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        checks.append(check(f"credential:{identity}:mode", mode == 0o640, oct(mode)))
        own_user = EXPECTED_USERS[identity]
        readable, msg = test_as_user(own_user, ["-r", str(path)])
        checks.append(check(f"credential:{identity}:own-readable", readable, msg or str(path)))
        for other, other_user in EXPECTED_USERS.items():
            if other == identity:
                continue
            # dashboard credential is intentionally readable by the dashboard only;
            # each component must be unable to read every other component secret.
            readable, msg = test_as_user(other_user, ["-r", str(path)])
            checks.append(check(
                f"credential:{identity}:blocked-from:{other}", not readable,
                msg or str(path),
            ))
    return checks


def systemd_checks(root: Path, backend: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not command_exists("systemctl"):
        return [check("systemctl", False, "systemctl unavailable")]

    roles = ["listener", "dashboard"] + (["maintenance"] if backend == "postgres" else [])
    props_by_role: dict[str, dict[str, str]] = {}
    for role in roles:
        unit = SERVICES[role]
        ok, detail = active_enabled(unit)
        checks.append(check(f"unit:{role}:active-enabled", ok, detail))
        try:
            props = unit_properties(unit)
            props_by_role[role] = props
        except Exception as exc:
            checks.append(check(f"unit:{role}:properties", False, str(exc)))
            continue
        checks.append(check(f"unit:{role}:user", props.get("User") == EXPECTED_USERS[role], props.get("User")))
        checks.append(check(f"unit:{role}:no-new-privileges", props.get("NoNewPrivileges") == "yes", props.get("NoNewPrivileges")))
        checks.append(check(f"unit:{role}:private-tmp", props.get("PrivateTmp") == "yes", props.get("PrivateTmp")))
        checks.append(check(f"unit:{role}:protect-home", props.get("ProtectHome") not in {"", "no"}, props.get("ProtectHome")))
        checks.append(check(f"unit:{role}:kernel-tunables", props.get("ProtectKernelTunables") == "yes", props.get("ProtectKernelTunables")))
        checks.append(check(f"unit:{role}:kernel-modules", props.get("ProtectKernelModules") == "yes", props.get("ProtectKernelModules")))
        checks.append(check(f"unit:{role}:control-groups", props.get("ProtectControlGroups") == "yes", props.get("ProtectControlGroups")))
        checks.append(check(f"unit:{role}:restrict-suid", props.get("RestrictSUIDSGID") == "yes", props.get("RestrictSUIDSGID")))
        checks.append(check(f"unit:{role}:lock-personality", props.get("LockPersonality") == "yes", props.get("LockPersonality")))
        af = set((props.get("RestrictAddressFamilies") or "").split())
        checks.append(check(f"unit:{role}:address-families", af <= {"AF_UNIX", "AF_INET", "AF_INET6"} and bool(af), sorted(af)))

        caps = (props.get("CapabilityBoundingSet") or "").lower()
        ambient = (props.get("AmbientCapabilities") or "").lower()
        if role == "listener":
            checks.append(check("unit:listener:capability-bounding", caps in {"cap_net_bind_service", "CAP_NET_BIND_SERVICE".lower()}, caps))
            checks.append(check("unit:listener:ambient-capability", ambient in {"cap_net_bind_service", "CAP_NET_BIND_SERVICE".lower()}, ambient))
            checks.append(check("unit:listener:protect-system", props.get("ProtectSystem") == "strict", props.get("ProtectSystem")))
        else:
            checks.append(check(f"unit:{role}:capability-bounding-empty", caps == "", caps))

        try:
            pid = int(props.get("MainPID") or "0")
        except ValueError:
            pid = 0
        if pid > 0 and Path(f"/proc/{pid}/status").exists():
            eff, amb = cap_mask_from_proc(pid)
            allowed = 1 << CAP_NET_BIND_SERVICE_BIT if role == "listener" else 0
            checks.append(check(f"process:{role}:effective-capabilities", eff & ~allowed == 0, hex(eff)))
            checks.append(check(f"process:{role}:ambient-capabilities", amb & ~allowed == 0, hex(amb)))
        else:
            checks.append(check(f"process:{role}:pid", False, pid))

    if backend == "postgres":
        ok, detail = active_enabled(TIMER)
        checks.append(check("unit:partition-timer:active-enabled", ok, detail))
        for role, user in EXPECTED_USERS.items():
            writable, msg = test_as_user(user, ["-w", str(root)])
            checks.append(check(f"source-tree-not-writable:{role}", not writable, msg or str(root)))
    return checks


def unit_verify_checks() -> list[dict[str, Any]]:
    if not command_exists("systemd-analyze"):
        return [check("systemd-analyze", False, "systemd-analyze unavailable")]
    files = [Path("/etc/systemd/system") / SERVICES["listener"], Path("/etc/systemd/system") / SERVICES["dashboard"]]
    maint = Path("/etc/systemd/system") / SERVICES["maintenance"]
    timer = Path("/etc/systemd/system") / TIMER
    files += [p for p in (maint, timer) if p.exists()]
    out = []
    for path in files:
        if not path.exists():
            out.append(check(f"systemd-analyze:{path.name}", False, "unit file missing"))
            continue
        cp = run(["systemd-analyze", "verify", str(path)], timeout=30)
        out.append(check(f"systemd-analyze:{path.name}", cp.returncode == 0, (cp.stderr or cp.stdout).strip()))
    return out


def socket_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not command_exists("ss"):
        return [check("socket:ss", False, "ss unavailable")]
    cp = run(["ss", "-H", "-lntup"])
    if cp.returncode != 0:
        return [check("socket:ss", False, cp.stderr.strip())]
    text = cp.stdout
    ports = config.get("listen_ports") or [514]
    try:
        ports = [int(p) for p in ports]
    except Exception:
        ports = [514]
    checks = [check(f"socket:syslog:{p}", f":{p}" in text, p) for p in ports]
    checks.append(check("socket:dashboard:8080", ":8080" in text, 8080))
    return checks


def selinux_checks(root: Path, require_enforcing: bool) -> list[dict[str, Any]]:
    if not command_exists("getenforce"):
        return [check("selinux:available", not require_enforcing, "getenforce unavailable", required=require_enforcing)]
    cp = run(["getenforce"])
    state = cp.stdout.strip()
    out = [check("selinux:state", state == "Enforcing" if require_enforcing else state in {"Enforcing", "Permissive", "Disabled"}, state, required=require_enforcing)]
    if state != "Enforcing":
        return out
    if command_exists("ls"):
        label = run(["ls", "-Zd", str(root)])
        txt = (label.stdout or label.stderr).strip()
        out.append(check("selinux:source-label", "user_home_t" not in txt, txt))
    if command_exists("ausearch"):
        avc = run(["ausearch", "-m", "AVC", "-ts", "boot"], timeout=30)
        text = (avc.stdout or "") + "\n" + (avc.stderr or "")
        needles = [str(root), "mini-siem", "siem-listener", "siem-maintenance"]
        relevant = [line for line in text.splitlines() if "avc:  denied" in line.lower() and any(n in line for n in needles)]
        out.append(check("selinux:no-relevant-avc", not relevant, relevant[:20]))
    else:
        out.append(check("selinux:avc-query", True, "ausearch unavailable; AVC query not collected", required=False))
    return out


def reboot_checks(phase: str, baseline: Path | None) -> list[dict[str, Any]]:
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    out = [check("boot-id-readable", bool(boot_id), boot_id)]
    if phase == "post-reboot":
        if baseline is None or not baseline.exists():
            out.append(check("reboot:baseline", False, "--baseline is required for post-reboot"))
        else:
            data = json.loads(baseline.read_text(encoding="utf-8"))
            before = str(data.get("host", {}).get("boot_id") or "")
            out.append(check("reboot:boot-id-changed", bool(before) and before != boot_id, {"before": before, "after": boot_id}))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", default=str(ROOT))
    ap.add_argument("--db-config", default=None)
    ap.add_argument("--output", required=True)
    ap.add_argument("--phase", choices=["current", "pre-reboot", "post-reboot"], default="current")
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--require-selinux-enforcing", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.project_root).resolve()
    config_path = Path(args.db_config).resolve() if args.db_config else root / "db-config.json"
    evidence: dict[str, Any] = {
        "schema": 1,
        "generated_at": utc_now(),
        "phase": args.phase,
        "project_root": str(root),
        "checks": [],
        "host": {},
    }
    try:
        backend, config = read_backend(config_path)
    except Exception as exc:
        evidence["checks"].append(check("db-config", False, str(exc)))
        backend, config = "unknown", {}
    evidence["backend"] = backend
    try:
        evidence["host"]["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        evidence["host"]["boot_id"] = ""

    runtime_ok, runtime_detail = systemd_runtime_available()
    evidence["checks"].append(check("environment:systemd-runtime", runtime_ok, runtime_detail))
    for user in EXPECTED_USERS.values():
        evidence["checks"].append(nonlogin_user_check(user))
    if backend in {"sqlite", "postgres"}:
        evidence["checks"] += credential_checks(root, backend)
        if runtime_ok:
            evidence["checks"] += systemd_checks(root, backend)
            evidence["checks"] += socket_checks(config)
            evidence["checks"] += unit_verify_checks()
    evidence["checks"] += selinux_checks(root, args.require_selinux_enforcing)
    evidence["checks"] += reboot_checks(args.phase, Path(args.baseline).resolve() if args.baseline else None)

    required_failures = [c for c in evidence["checks"] if c.get("required", True) and not c.get("ok")]
    environment_markers = {"environment:systemd-runtime", "systemctl", "systemd-analyze", "selinux:available"}
    blocked = any(c["name"] in environment_markers and not c["ok"] for c in required_failures)
    evidence["status"] = "BLOCKED_ENVIRONMENT" if blocked else ("FAIL" if required_failures else "PASS")
    evidence["summary"] = {
        "total": len(evidence["checks"]),
        "passed": sum(1 for c in evidence["checks"] if c["ok"]),
        "required_failed": len(required_failures),
    }
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": evidence["status"], "output": str(output), **evidence["summary"]}, sort_keys=True))
    return 0 if evidence["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
