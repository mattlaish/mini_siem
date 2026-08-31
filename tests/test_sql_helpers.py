import pytest

from sql_helpers import identifier, placeholders, in_clause, sqlite_integrity_pragma


def test_placeholders_are_parameter_only():
    assert placeholders(3) == "?,?,?"
    with pytest.raises(ValueError):
        placeholders(0)


def test_identifier_rejects_injection_tokens():
    assert identifier("l.received_at") == "l.received_at"
    with pytest.raises(ValueError):
        identifier("received_at DESC; DROP TABLE logs")


def test_in_clause_keeps_values_out_of_sql():
    sql, params = in_clause("id", [1, "2 OR 1=1"])
    assert sql == "id IN (?,?)"
    assert params == [1, "2 OR 1=1"]
    assert "OR 1=1" not in sql


def test_integrity_pragma_is_allowlisted():
    assert sqlite_integrity_pragma(quick=True) == "quick_check"
    assert sqlite_integrity_pragma(quick=False) == "integrity_check"
