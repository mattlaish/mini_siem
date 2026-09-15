# Phase 12.11 runtime authorization implementation reference

ROLES = {
    "VIEWER": {"read"},
    "OPERATOR": {"read", "operate"},
    "ADMIN": {"read", "operate", "configure"},
    "MIGRATION_OWNER": {"migration"},
}

def is_allowed(role, action):
    return action in ROLES.get(role, set())
