# Database-backed RBAC Validation

Scope:
Validate RBAC decisions against persisted role and permission data.

Validation cases:

| Case | Expected |
|---|---|
| Existing user + allowed permission | ALLOW |
| Existing user + denied permission | DENY |
| Missing role mapping | DENY |
| Unknown permission | DENY |

Status:
LOCAL VALIDATION PREPARED

Production database execution remains environment dependent.
