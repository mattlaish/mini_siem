import json
import unittest
from unittest import mock

import api_poller


class _Response:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


class _Manager:
    def resolve_secret(self, row):
        return "test-secret"


class SophosFlowTest(unittest.TestCase):
    def test_token_whoami_region_header_and_cursor(self):
        row = {
            "auth_scheme": "oauth2_sophos",
            "token_url": "https://id.sophos.test/token",
            "events_url": "/siem/v1/events",
            "whoami_url": "https://api.sophos.test/whoami/v1",
            "tenant_header": "",
            "client_id": "test-client",
            "scope": "token",
            "cursor": "cursor-1",
        }
        responses = [
            _Response({"access_token": "jwt-test"}),
            _Response({
                "id": "tenant-test",
                "idType": "tenant",
                "apiHosts": {"dataRegion": "https://api-region.sophos.test"},
            }),
            _Response({"items": [{"id": "event-1"}], "next_cursor": "cursor-2"}),
        ]
        requests = []

        def fake_urlopen(request, timeout):
            requests.append(request)
            return responses.pop(0)

        poller = api_poller._PollerThread(1, _Manager())
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            items, cursor = poller._poll_once(row)

        self.assertEqual(items, [{"id": "event-1"}])
        self.assertEqual(cursor, "cursor-2")
        self.assertEqual(requests[1].headers["Authorization"], "Bearer jwt-test")
        self.assertNotIn("X-tenant-id", requests[1].headers)
        self.assertEqual(requests[2].headers["X-tenant-id"], "tenant-test")
        self.assertEqual(
            requests[2].full_url,
            "https://api-region.sophos.test/siem/v1/events?cursor=cursor-1",
        )

    def test_first_request_uses_official_from_date_parameter(self):
        row = {
            "auth_scheme": "oauth2_sophos",
            "events_url": "/siem/v1/events",
            "cursor": None,
            "initial_lookback_seconds": 3600,
        }
        poller = api_poller._PollerThread(1, _Manager())
        poller._data_region = "https://api-region.sophos.test"
        poller._valid_token = lambda unused_row: "jwt-test"
        poller._discover = lambda unused_row, unused_token: None
        captured = {}

        def fake_http(request, phase, timeout=20):
            captured["url"] = request.full_url
            return {"items": [], "next_cursor": "cursor-first"}

        poller._http_json = fake_http
        with mock.patch("time.time", return_value=2_000_000_000):
            items, cursor = poller._poll_once(row)

        self.assertEqual(items, [])
        self.assertEqual(cursor, "cursor-first")
        self.assertIn("from_date=1999996400", captured["url"])
        self.assertNotIn("?from=", captured["url"])


if __name__ == "__main__":
    unittest.main()
