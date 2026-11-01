# Secret redaction pipeline baseline

SENSITIVE_KEYS = {
    "password",
    "token",
    "secret",
    "private_key",
}

def redact_mapping(data):
    return {
        key: ("[REDACTED]" if key.lower() in SENSITIVE_KEYS else value)
        for key, value in data.items()
    }
