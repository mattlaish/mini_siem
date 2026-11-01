# Tenant runtime enforcement baseline

def enforce_tenant(object_tenant, request_tenant):
    if object_tenant != request_tenant:
        raise PermissionError("tenant boundary violation")
    return True
