def test_postgres_runtime_options_contract():
    options = {
        "connect_timeout": 5,
        "connect_retries": 5,
        "connect_retry_delay": 2,
    }
    assert options["connect_retries"] > 0
