"""Optional live OpenAI smoke test.

Disabled by default. Set MINISIEM_OPENAI_LIVE_TEST=1 and OPENAI_API_KEY to run
against api.openai.com. No SIEM log data is used; the test sends a fixed probe.
"""
import os

import pytest

import ai_soc


@pytest.mark.skipif(os.environ.get("MINISIEM_OPENAI_LIVE_TEST") != "1", reason="live OpenAI test is opt-in")
def test_live_openai_responses_smoke():
    key = os.environ.get("OPENAI_API_KEY") or ""
    if not key:
        pytest.skip("OPENAI_API_KEY not set")
    model = os.environ.get("MINISIEM_OPENAI_TEST_MODEL", "gpt-5.6-luna")
    client = ai_soc.LLMClient(
        "https://api.openai.com/v1", model, key, timeout=60, max_retries=2,
        external_mode=True, redaction_policy="strict",
    )
    reply = client.chat([{"role": "user", "content": "Reply with the single word: ready"}], max_tokens=128)
    assert "ready" in reply.lower()
