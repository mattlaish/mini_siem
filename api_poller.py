"""api_poller — background OAuth2 client-credentials log pullers.

Generic version of the hand-written Sophos puller: for each enabled row in
api_pollers, a background thread fetches an OAuth2 token (refreshing ~5 min
before the assumed 60-min expiry), polls the events URL with a cursor
bookmark, and pushes returned events into the same ingest path the syslog
listener uses (store -> rules -> IOC -> field index).

Zero external dependencies: urllib from the stdlib, not requests.

Secret handling: client_secret is stored either encrypted (secretbox) or,
in future, brokered by VaultGate. This module asks a resolver callback for
the plaintext secret at token-fetch time so it never has to know the storage
mechanism.
"""

import json
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Refresh the token this many seconds before we assume it expires. The Sophos
# script used 55 min against a 60 min token; 300s early on a 3600s token.
_TOKEN_TTL_SECONDS = 3600
_TOKEN_REFRESH_EARLY = 300


class _PollerThread:
    def __init__(self, row_id, manager):
        self.row_id = row_id
        self.mgr = manager
        self._stop = threading.Event()
        self._token = None
        self._token_at = 0.0
        self._thread = None
        # cached whoami discovery (tenant/partner/org id + data-region host)
        self._whoami_id = None
        self._whoami_id_type = None
        self._data_region = None
        self._whoami_at = 0.0

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    # -- token / auth ------------------------------------------------------
    def _scheme(self, row):
        return (row.get("auth_scheme") or "oauth2_client_credentials").lower()

    def _valid_token(self, row):
        # api_key scheme has no token — auth is a static header per request.
        if self._scheme(row) == "api_key":
            return None
        age = time.time() - self._token_at
        if self._token and age < (_TOKEN_TTL_SECONDS - _TOKEN_REFRESH_EARLY):
            return self._token
        return self._fetch_token(row)

    def _fetch_token(self, row):
        secret = self.mgr.resolve_secret(row)
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": row["client_id"],
            "client_secret": secret or "",
            "scope": row["scope"] or "token",
        }).encode("ascii")
        req = urllib.request.Request(
            row["token_url"], data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        body = self._http_json(req, "token", timeout=15)
        self._token = body.get("access_token")
        self._token_at = time.time()
        if not self._token:
            raise RuntimeError("[token] response had no access_token")
        return self._token

    def _auth_headers(self, row, token):
        """Per-request auth headers for the configured scheme."""
        scheme = self._scheme(row)
        if scheme == "api_key":
            # static key placed in a caller-named header (default X-API-Key).
            header = (row.get("api_key_header") or "X-API-Key").strip()
            secret = self.mgr.resolve_secret(row)
            return {header: secret or ""}
        # oauth2 variants: Bearer token
        return {"Authorization": f"Bearer {token}"}

    # -- whoami discovery (only for the sophos scheme) --------------------
    def _discover(self, row, token):
        """For the oauth2_sophos scheme, call the whoami URL with the Bearer
        token to learn the tenant/partner/org id and data-region host.
        Sophos: GET /whoami/v1 -> {id, idType, apiHosts:{dataRegion}}.
        No X-*-ID header is sent to whoami itself (per Sophos docs)."""
        if self._scheme(row) != "oauth2_sophos":
            return
        whoami_url = (row.get("whoami_url") or "").strip()
        if not whoami_url:
            return
        if self._whoami_id and self._whoami_at >= self._token_at:
            return
        req = urllib.request.Request(whoami_url, headers={
            "Authorization": f"Bearer {token}"})
        body = self._http_json(req, "whoami", timeout=15)
        self._whoami_id = body.get("id")
        self._whoami_id_type = body.get("idType")
        hosts = body.get("apiHosts") or {}
        self._data_region = hosts.get("dataRegion") or hosts.get("global")
        self._whoami_at = time.time()

    def _tenant_header(self, row):
        """The X-Tenant-ID / X-Partner-ID / X-Organization-ID header for the
        discovered principal. A custom header name can override the default."""
        if not self._whoami_id or not self._whoami_id_type:
            return {}
        override = (row.get("tenant_header") or "").strip()
        if override:
            return {override: self._whoami_id}
        name = {
            "tenant": "X-Tenant-ID",
            "partner": "X-Partner-ID",
            "organization": "X-Organization-ID",
        }.get(self._whoami_id_type)
        return {name: self._whoami_id} if name else {}

    def _resolve_events_url(self, row):
        events = (row["events_url"] or "").strip()
        # absolute URL: use as-is.
        if events.startswith("http://") or events.startswith("https://"):
            return events
        # otherwise treat it as a path to join onto the discovered data-region
        # host. Tolerate a missing leading slash so 'siem/v1/events' and
        # '/siem/v1/events' both work — a bare path without the host is the
        # cause of Sophos "Unable to identify proxy for host" errors.
        if self._data_region:
            path = events if events.startswith("/") else "/" + events
            return self._data_region.rstrip("/") + path
        return events

    # -- poll --------------------------------------------------------------
    def _poll_once(self, row):
        token = self._valid_token(row)
        self._discover(row, token)          # sophos scheme only
        params = {}
        cursor = row.get("cursor")
        if cursor:
            params["cursor"] = cursor
        else:
            lookback = int(row.get("initial_lookback_seconds") or 86400)
            params["from"] = int(time.time()) - lookback
        url = self._resolve_events_url(row)
        if params:
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        headers = {"X-Locale": "en"}
        headers.update(self._auth_headers(row, token))   # scheme-specific auth
        headers.update(self._tenant_header(row))         # sophos tenant header
        req = urllib.request.Request(url, headers=headers)
        body = self._http_json(req, "events", timeout=20)
        items = body.get("items", []) or []
        next_cursor = body.get("next_cursor") or cursor
        return items, next_cursor

    def _http_json(self, req, phase, timeout=20):
        """urlopen + json parse, but on HTTPError capture the response body
        (APIs put the real reason there) and tag which phase failed."""
        import urllib.error
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            raise RuntimeError(f"[{phase}] HTTP {e.code} {e.reason}"
                               + (f" — {detail}" if detail else "")) from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"[{phase}] connection failed: {e.reason}") from None
        except json.JSONDecodeError:
            raise RuntimeError(f"[{phase}] response was not valid JSON") from None

    def _loop(self):
        while not self._stop.is_set():
            row = self.mgr.get_row(self.row_id)
            if not row or not row["enabled"]:
                break
            interval = max(15, int(row.get("interval_seconds") or 60))
            try:
                items, next_cursor = self._poll_once(row)
                if items:
                    self.mgr.ingest_batch(row, items)
                self.mgr.record_success(self.row_id, len(items), next_cursor)
            except Exception as exc:  # noqa: BLE001 — surface any error to the UI
                msg = str(exc) if str(exc) else f"{type(exc).__name__}"
                self.mgr.record_error(self.row_id, msg)
            # sleep in small slices so stop() is responsive
            waited = 0
            while waited < interval and not self._stop.is_set():
                time.sleep(min(2, interval - waited))
                waited += 2


class PollerManager:
    """Owns the poller threads; reconciles them with the api_pollers table."""

    def __init__(self, conn_factory, ingest_fn, resolve_secret_fn):
        self._conn_factory = conn_factory
        self._ingest_fn = ingest_fn                # (event_dict) -> None
        self._resolve_secret = resolve_secret_fn   # (row) -> plaintext secret
        self._threads = {}
        self._lock = threading.Lock()
        self._reconcile_stop = threading.Event()

    def start(self):
        self._reconcile()
        threading.Thread(target=self._reconcile_loop, daemon=True).start()

    def _reconcile_loop(self):
        while not self._reconcile_stop.is_set():
            time.sleep(10)
            try:
                self._reconcile()
            except Exception:
                pass

    def _reconcile(self):
        rows = {r["id"]: r for r in self._enabled_rows()}
        with self._lock:
            # stop threads whose row is gone or disabled
            for rid in list(self._threads):
                if rid not in rows:
                    self._threads[rid].stop()
                    del self._threads[rid]
            # start threads for newly-enabled rows
            for rid in rows:
                if rid not in self._threads:
                    t = _PollerThread(rid, self)
                    self._threads[rid] = t
                    t.start()

    # -- data access used by threads --------------------------------------
    def _enabled_rows(self):
        conn = self._conn_factory()
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM api_pollers WHERE enabled=1").fetchall()]
        conn.close()
        return rows

    def get_row(self, rid):
        conn = self._conn_factory()
        r = conn.execute("SELECT * FROM api_pollers WHERE id=?", (rid,)).fetchone()
        conn.close()
        return dict(r) if r else None

    def resolve_secret(self, row):
        return self._resolve_secret(row)

    def ingest_batch(self, row, items):
        for item in items:
            event = self._event_from_item(row, item)
            self._ingest_fn(event)

    def _event_from_item(self, row, item):
        """Turn one API event dict into a normalized event for the pipeline.
        The connector name travels as _connector so the dashboard can use it
        as the SOURCE; the endpoint IP (if any) is surfaced as a field."""
        if not isinstance(item, dict):
            item = {"message": str(item)}
        # surface a nested endpoint IP (e.g. Sophos source_info.ip) as a
        # top-level field so it's searchable and usable as source detail.
        endpoint_ip = ""
        si = item.get("source_info")
        if isinstance(si, dict):
            endpoint_ip = si.get("ip") or ""
        endpoint_ip = endpoint_ip or item.get("ip") or ""
        return {
            "_connector": row["name"],
            "_endpoint_ip": str(endpoint_ip),
            "_json": item,
        }

    def record_success(self, rid, n, cursor):
        conn = self._conn_factory()
        conn.execute(
            "UPDATE api_pollers SET cursor=?, pulled_count=pulled_count+?, "
            "last_poll_at=?, last_error=NULL WHERE id=?",
            (cursor, n, datetime.now(timezone.utc).isoformat(), rid))
        conn.commit(); conn.close()

    def record_error(self, rid, msg):
        conn = self._conn_factory()
        conn.execute(
            "UPDATE api_pollers SET last_poll_at=?, last_error=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), msg[:500], rid))
        conn.commit(); conn.close()
