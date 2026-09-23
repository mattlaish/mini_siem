"""Alert workflow state machine shared by API/UI tests.

The SIEM owns only lightweight alert triage state.  External ticketing/SOAR may
remain the incident system of record.
"""

STATES = ("new", "acknowledged", "investigating", "resolved", "closed")
TRANSITIONS = {
    "new": {"acknowledged", "investigating", "resolved"},
    "acknowledged": {"investigating", "resolved"},
    "investigating": {"resolved"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
}


def normalize(value) -> str:
    return str(value or "new").strip().lower()


def validate_transition(current, target) -> tuple[str, str]:
    current = normalize(current)
    target = normalize(target)
    if current not in STATES:
        current = "new"
    if target not in STATES:
        raise ValueError(f"invalid alert workflow status: {target}")
    if target != current and target not in TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid alert workflow transition {current} -> {target}")
    return current, target
