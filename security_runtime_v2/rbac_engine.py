# Phase 12.13 RBAC runtime engine baseline

ROLE_PERMISSIONS = {
    "VIEWER": {"read"},
    "OPERATOR": {"read", "operate"},
    "ADMIN": {"read", "operate", "configure"},
}

def authorize(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, set())
