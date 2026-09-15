# Secret handling runtime helper

SENSITIVE_FIELDS = {
    "password",
    "token",
    "secret",
    "private_key",
}

def redact(value):
    if value is None:
        return None
    return "[REDACTED]"
