"""Small, audited helpers for composing the non-value parts of SQL.

Values must still be passed separately to ``Connection.execute``.  These
helpers only build placeholder lists or select identifiers/operators from an
explicit allow-list, keeping dynamic SQL construction in one reviewable place.
"""


def placeholders(count: int) -> str:
    if count <= 0:
        raise ValueError("placeholder count must be positive")
    return ",".join("?" for _ in range(count))


def allowlisted(value: str, allowed, *, default=None, label="SQL token") -> str:
    if isinstance(allowed, dict):
        if value in allowed:
            return allowed[value]
    elif value in allowed:
        return value
    if default is not None:
        return default
    raise ValueError(f"invalid {label}: {value!r}")


def order_direction(value: str, *, default="DESC") -> str:
    return "ASC" if str(value).lower() == "asc" else default


def sqlite_integrity_pragma(*, quick: bool) -> str:
    return allowlisted(
        "quick_check" if quick else "integrity_check",
        {"quick_check", "integrity_check"},
        label="SQLite integrity pragma",
    )


def identifier(value: str, *, allowed=None, label="SQL identifier") -> str:
    """Return a SQL identifier only after syntactic and optional allow-list validation."""
    import re
    text = str(value or "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", text):
        raise ValueError(f"invalid {label}: {value!r}")
    if allowed is not None and text not in allowed:
        raise ValueError(f"invalid {label}: {value!r}")
    return text


def in_clause(column: str, values, *, allowed_columns=None):
    vals = list(values)
    col = identifier(column, allowed=allowed_columns)
    return f"{col} IN ({placeholders(len(vals))})", vals


def not_in_clause(column: str, values, *, allowed_columns=None):
    vals = list(values)
    col = identifier(column, allowed=allowed_columns)
    return f"{col} NOT IN ({placeholders(len(vals))})", vals


def where_clause(clauses) -> str:
    parts = [str(c).strip() for c in clauses if str(c).strip()]
    return "WHERE " + " AND ".join(parts) if parts else ""


def select_in(table: str, columns: str, column: str, values, *, suffix: str = "") -> tuple[str, list]:
    """Build a SELECT with one parameterized IN predicate.

    Table/column identifiers are syntax-validated. ``columns`` and ``suffix``
    are intentionally call-site-owned static SQL fragments; callers must not
    pass request/user input into them.
    """
    safe_table = identifier(table)
    safe_column = identifier(column)
    vals = list(values)
    return ("SELECT " + columns + " FROM " + safe_table + " WHERE " + safe_column
            + " IN (" + placeholders(len(vals)) + ")" + suffix, vals)
