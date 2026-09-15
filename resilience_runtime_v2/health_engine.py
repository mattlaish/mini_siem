# Health state engine baseline

def calculate_health(checks):
    if all(value == "PASS" for value in checks.values()):
        return "HEALTHY"
    return "DEGRADED"
