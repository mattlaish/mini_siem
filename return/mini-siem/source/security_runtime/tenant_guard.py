# Tenant isolation enforcement reference

def tenant_match(object_tenant, request_tenant):
    return object_tenant == request_tenant
