"""Progressive investigation profile definitions for AI triage.

Trigger policy is intentionally NOT defined here.  Rules decide whether an
alert exists.  This module only decides how far related evidence should be
searched once a legitimate alert enters AI triage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class StageWindow:
    before_seconds: int
    after_seconds: int
    candidate_limit: int
    evidence_limit: int


@dataclass(frozen=True)
class InvestigationProfile:
    key: str
    label: str
    stages: Mapping[str, StageWindow]


STAGE_ORDER = ("short", "medium", "long")


PROFILES = {
    "auth_anomaly": InvestigationProfile(
        key="auth_anomaly",
        label="Authentication anomaly / NXLog 4625",
        stages={
            "short": StageWindow(5 * 60, 10 * 60, 100, 80),
            "medium": StageWindow(15 * 60, 30 * 60, 250, 120),
            "long": StageWindow(60 * 60, 2 * 60 * 60, 1000, 120),
        },
    ),
    "malware_sophos": InvestigationProfile(
        key="malware_sophos",
        label="Malware / Sophos detection",
        stages={
            "short": StageWindow(2 * 60 * 60, 60 * 60, 100, 80),
            "medium": StageWindow(6 * 60 * 60, 3 * 60 * 60, 250, 120),
            "long": StageWindow(24 * 60 * 60, 12 * 60 * 60, 1200, 120),
        },
    ),
    "ioc_hit": InvestigationProfile(
        key="ioc_hit",
        label="IOC hit",
        stages={
            "short": StageWindow(4 * 60 * 60, 60 * 60, 100, 80),
            "medium": StageWindow(12 * 60 * 60, 3 * 60 * 60, 250, 120),
            "long": StageWindow(48 * 60 * 60, 12 * 60 * 60, 1500, 120),
        },
    ),
    "account_privilege": InvestigationProfile(
        key="account_privilege",
        label="Account creation / privilege change",
        stages={
            "short": StageWindow(15 * 60, 60 * 60, 100, 80),
            "medium": StageWindow(45 * 60, 3 * 60 * 60, 250, 120),
            "long": StageWindow(3 * 60 * 60, 10 * 60 * 60, 1200, 120),
        },
    ),
    "firewall_c2": InvestigationProfile(
        key="firewall_c2",
        label="Firewall C2 / beaconing",
        stages={
            "short": StageWindow(60 * 60, 30 * 60, 100, 80),
            "medium": StageWindow(3 * 60 * 60, 90 * 60, 250, 120),
            "long": StageWindow(12 * 60 * 60, 5 * 60 * 60, 1500, 120),
        },
    ),
    # Safe fallback for existing alert types that do not belong to one of the
    # five explicit product profiles.  This does not change trigger behavior.
    "generic": InvestigationProfile(
        key="generic",
        label="Generic security event",
        stages={
            "short": StageWindow(15 * 60, 15 * 60, 100, 80),
            "medium": StageWindow(45 * 60, 45 * 60, 250, 120),
            "long": StageWindow(150 * 60, 150 * 60, 1000, 120),
        },
    ),
}


_ACCOUNT_PRIVILEGE_EVENT_IDS = {
    "4672", "4719", "4720", "4722", "4723", "4724", "4725", "4726",
    "4728", "4729", "4732", "4733", "4738", "4756", "4757",
}
_AUTH_EVENT_IDS = {"4625", "4648", "4740"}
_MALWARE_WORDS = (
    "malware", "trojan", "ransomware", "virus", "quarantin", "infected",
    "threat detected", "detection", "exploit", "pua", "potentially unwanted",
)
_C2_WORDS = ("command and control", "command-and-control", " c2 ", "beacon", "beaconing")
_AUTH_WORDS = ("failed logon", "login failed", "authentication failure", "brute-force", "brute force")


def _get(row, key, default=""):
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        try:
            value = row.get(key, default)
        except AttributeError:
            return default
    return default if value is None else value


def _linked_text(linked_rows: Iterable) -> str:
    parts = []
    for row in linked_rows or ():
        for key in ("app_name", "message", "msg_id", "source_ip", "hostname"):
            value = str(_get(row, key, "") or "").strip()
            if value:
                parts.append(value)
    return " ".join(parts).lower()


def classify_investigation(alert, linked_rows: Iterable) -> InvestigationProfile:
    """Choose the related-evidence profile for an already-triggered alert.

    This function never decides whether the alert should exist or enter AI.
    It only classifies the investigation after trigger policy has fired.
    """
    rule = str(_get(alert, "rule_name", "") or "").lower()
    description = str(_get(alert, "description", "") or "").lower()
    text = " ".join((rule, description, _linked_text(linked_rows)))

    if rule == "threat_intel_match" or "ioc match" in text:
        return PROFILES["ioc_hit"]

    # Explicit Windows account/privilege event IDs take priority over broad
    # malware/auth keywords to avoid misclassification from free-text messages.
    linked_ids = {str(_get(row, "msg_id", "") or "").strip() for row in linked_rows or ()}
    if linked_ids & _ACCOUNT_PRIVILEGE_EVENT_IDS:
        return PROFILES["account_privilege"]
    if linked_ids & _AUTH_EVENT_IDS:
        return PROFILES["auth_anomaly"]

    if any(word in text for word in _MALWARE_WORDS):
        return PROFILES["malware_sophos"]

    if any(word in text for word in _C2_WORDS) or "c2" in rule or "beacon" in rule:
        return PROFILES["firewall_c2"]

    if any(word in text for word in _AUTH_WORDS) or rule in {
        "ssh_bruteforce", "repeated_login_failures"
    }:
        return PROFILES["auth_anomaly"]

    return PROFILES["generic"]
