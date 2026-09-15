# Runtime health collector reference

def collect_health(checks):
    results = []
    overall = "HEALTHY"

    for name, result in checks.items():
        results.append({"name": name, "status": result})

    if any(x["status"] != "PASS" for x in results):
        overall = "DEGRADED"

    return {
        "status": overall,
        "checks": results,
    }
