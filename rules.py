"""
mini-SIEM rule engine
======================
A small, dependency-free correlation engine. Each rule inspects
incoming log events (already parsed) and maintains its own sliding
window of state; when a threshold is crossed it writes a row to the
`alerts` table via Storage.insert_alert().

Add new rules by subclassing Rule and appending an instance to
RuleEngine.rules in __init__.
"""

import re
import time
from collections import defaultdict, deque

import severity as severity_mod


IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def extract_ip(text: str):
    m = IP_RE.search(text or "")
    return m.group(1) if m else None


class Rule:
    name = "base_rule"
    severity = "warning"

    def evaluate(self, log_id: int, event: dict, storage):
        """Return None, or (source_ip, description, [log_ids]) if the rule fires."""
        raise NotImplementedError


class ThresholdRule(Rule):
    """Fires when `pattern` matches an event's message `threshold` times
    from the same key (default: source IP extracted from the message,
    falling back to the packet's source_ip) within `window_seconds`."""

    def __init__(self, name, pattern, threshold, window_seconds, severity="warning",
                 description=None, key_from_message=True):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.severity = severity
        self.description = description or f"{name}: {threshold}+ matches in {window_seconds}s"
        self.key_from_message = key_from_message
        self._hits = defaultdict(deque)  # key -> deque[(timestamp, log_id)]

    def evaluate(self, log_id: int, event: dict, storage):
        text = event.get("message", "")
        if not self.pattern.search(text):
            return None

        key = None
        if self.key_from_message:
            key = extract_ip(text)
        key = key or event.get("source_ip") or "unknown"

        now = time.time()
        dq = self._hits[key]
        dq.append((now, log_id))
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if len(dq) >= self.threshold:
            log_ids = [i for _, i in dq]
            desc = f"{self.description} (source: {key}, {len(dq)} hits)"
            dq.clear()  # avoid re-alerting on every subsequent hit within the same burst
            return key, desc, log_ids
        return None


class SeverityRule(Rule):
    """Fires immediately on any event at or above a given syslog severity
    (emergency/alert/critical/error), no threshold needed."""

    HIGH_SEVERITIES = {"emergency", "alert", "critical"}

    def __init__(self, name="high_severity_event", severity="critical"):
        self.name = name
        self.severity = severity

    def evaluate(self, log_id: int, event: dict, storage):
        sev = severity_mod.normalize(event.get("severity"))
        if sev in self.HIGH_SEVERITIES:
            src = event.get("source_ip") or "unknown"
            desc = f"Device reported {sev} severity event: {event.get('message', '')[:200]}"
            return src, desc, [log_id]
        return None


class RuleEngine:
    def __init__(self, storage):
        self.storage = storage
        self.rules = [
            ThresholdRule(
                name="ssh_bruteforce",
                pattern=r"failed password|authentication failure|invalid user",
                threshold=5,
                window_seconds=60,
                severity="critical",
                description="Possible SSH brute-force attempt",
            ),
            ThresholdRule(
                name="firewall_deny_burst",
                pattern=r"\b(deny|denied|block|blocked|drop|dropped)\b",
                threshold=20,
                window_seconds=60,
                severity="warning",
                description="Burst of firewall denies (possible scan)",
            ),
            ThresholdRule(
                name="repeated_login_failures",
                pattern=r"login failed|access denied|unauthorized",
                threshold=8,
                window_seconds=120,
                severity="warning",
                description="Repeated login/access failures",
            ),
            SeverityRule(name="high_severity_event", severity="critical"),
        ]

    def process(self, log_id: int, event: dict):
        for rule in self.rules:
            result = rule.evaluate(log_id, event, self.storage)
            if result:
                source_ip, description, log_ids = result
                self.storage.insert_alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    source_ip=source_ip,
                    description=description,
                    log_ids=log_ids,
                )
                print(f"  [ALERT] {rule.name} ({rule.severity}) — {description}")
