"""
mini-SIEM severity normalization
=================================
One shared vocabulary for syslog severities, so that real-world
variants ("information", "info", "warn", "err", "crit", "fatal",
"panic", "verbose", ...) all map onto the same canonical levels and
compare/filter consistently everywhere: parsing (listener), search
filters (dashboard), forwarding thresholds (forwarder), live rules
(rules), and retrospective correlations (correlations).

Canonical levels (standard syslog order, most severe first):
    emergency, alert, critical, error, warning, notice, informational, debug
"""

import re

CANONICAL = [
    "emergency", "alert", "critical", "error",
    "warning", "notice", "informational", "debug",
]

ORDER = {name: i for i, name in enumerate(CANONICAL)}

# variant (lowercase) -> canonical
_SYNONYMS = {
    "emergency": "emergency", "emerg": "emergency", "panic": "emergency",
    "alert": "alert",
    "critical": "critical", "crit": "critical", "fatal": "critical",
    "error": "error", "err": "error",
    "warning": "warning", "warn": "warning",
    "notice": "notice",
    "informational": "informational", "information": "informational",
    "info": "informational", "informative": "informational",
    "debug": "debug", "verbose": "debug", "trace": "debug",
}


def normalize(value) -> str:
    """Map any severity spelling to its canonical name.
    Returns "" if the value isn't recognizable as a severity."""
    return _SYNONYMS.get((value or "").strip().lower(), "")


def synonyms_of(canonical: str) -> list:
    """All spellings that map to a canonical level (includes itself).
    Useful for SQL `LOWER(severity) IN (...)` matching against data
    stored with non-canonical spellings."""
    canonical = normalize(canonical) or canonical
    return [k for k, v in _SYNONYMS.items() if v == canonical]


def index_of(value, default: int = 6) -> int:
    """Numeric severity (0 = most severe). Unrecognized values get
    `default` (informational), matching the documented forwarding
    behavior for unparseable severities."""
    canon = normalize(value)
    if canon in ORDER:
        return ORDER[canon]
    return default


# For classifying messages whose syslog PRI couldn't be parsed:
# look for severity keywords in the text and take the most severe hit.
_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(sorted(_SYNONYMS.keys(), key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


def extract_from_text(text: str) -> str:
    """Best-effort severity classification from message text (used only
    when the PRI header is absent/unparseable). Returns the canonical
    name of the most severe keyword found, or ""."""
    hits = _KEYWORD_RE.findall(text or "")
    if not hits:
        return ""
    best = min(ORDER[_SYNONYMS[h.lower()]] for h in hits)
    return CANONICAL[best]
