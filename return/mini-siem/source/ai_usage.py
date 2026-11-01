"""Provider/model usage estimates using explicit operator-supplied USD rates."""
import json
import math

KEY = "ai_usage_rates_v1"


def validate_rates(rates):
    if not isinstance(rates, list) or len(rates) > 50:
        raise ValueError("rates must be a list of at most 50 provider/model rates")
    seen = set()
    for row in rates:
        if not isinstance(row, dict) or set(row) != {"provider", "model", "input", "cached", "output"}:
            raise ValueError("Each rate needs provider, model, input, cached and output")
        for key in ("provider", "model"):
            if not isinstance(row[key], str) or not row[key].strip() or len(row[key]) > 200:
                raise ValueError("provider/model must be non-empty strings")
        pair = row["provider"], row["model"]
        if pair in seen:
            raise ValueError("Duplicate provider/model rate")
        seen.add(pair)
        for key in ("input", "cached", "output"):
            value = row[key]
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100000:
                raise ValueError("USD rates per million tokens must be finite and nonnegative")
    return rates


def load_rates(conn):
    row = conn.execute("SELECT value FROM app_config WHERE key=?", (KEY,)).fetchone()
    return validate_rates(json.loads(row["value"])) if row else []


def estimate(groups, rates):
    catalog = {(r["provider"], r["model"]): r for r in rates}
    amount, unpriced = 0.0, 0
    for group in groups:
        rate = catalog.get((group["provider"], group["model"]))
        if rate is None:
            unpriced += group["calls"]
            group["estimated_usd"] = None
            continue
        cached = min(group["input_tokens"], group["cached_tokens"])
        cost = ((group["input_tokens"] - cached) * rate["input"] + cached * rate["cached"] + group["output_tokens"] * rate["output"]) / 1_000_000
        group["estimated_usd"] = round(cost, 6)
        amount += cost
    return {"currency": "USD", "estimated_usd": round(amount, 6) if rates else None,
            "unpriced_calls": unpriced, "basis": "All retained calls repriced using current operator rates; estimate only, not a provider invoice"}
