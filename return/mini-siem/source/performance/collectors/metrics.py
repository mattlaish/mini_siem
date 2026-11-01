"""Common metric record format for Phase 12.4 benchmarks."""

def metric(component, name, value, unit):
    return {"component": component, "metric": name, "value": value, "unit": unit}
