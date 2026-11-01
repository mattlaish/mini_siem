"""DNS-pinned, bounded HTTP for pollers, feeds, tickets and AI.

Internal destinations require exact origins in MINISIEM_OUTBOUND_ALLOWLIST.
Redirects, metadata destinations and environment proxies are not permitted.
"""
import http.client
import io
import ipaddress
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse


class OutboundPolicyError(ValueError):
    pass


_SLOTS = threading.BoundedSemaphore(4)
JSON_LIMIT = 8 * 1024 * 1024
FEED_LIMIT = 16 * 1024 * 1024
AI_LIMIT = 4 * 1024 * 1024


def origin(url):
    try:
        p = urllib.parse.urlsplit(url)
        if (p.scheme not in ("http", "https") or not p.hostname or p.username is not None
                or p.password is not None or p.fragment or "\\" in url
                or any(ord(c) < 33 for c in url)):
            raise ValueError
        host = p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        if not 1 <= port <= 65535: raise ValueError
        return p.scheme, host, port
    except (ValueError, UnicodeError):
        raise OutboundPolicyError("Use an absolute HTTP(S) URL without credentials or fragments") from None


def _allowed_origins():
    result = set()
    for value in os.environ.get("MINISIEM_OUTBOUND_ALLOWLIST", "").split(","):
        value = value.strip()
        if not value: continue
        p = urllib.parse.urlsplit(value)
        if p.path not in ("", "/") or p.query:
            raise OutboundPolicyError("Outbound allowlist entries must be exact origins, not paths")
        result.add(origin(value))
    return result


def resolve_destination(url, *, purpose="generic", allow_loopback=False):
    scheme, host, port = origin(url)
    if host in {"metadata.google.internal", "metadata.goog"}:
        raise OutboundPolicyError("Metadata destinations are blocked")
    explicit = (scheme, host, port) in _allowed_origins()
    local = purpose == "ai_local" and host in {"localhost", "127.0.0.1", "::1"} and port in {11434, 1234}
    dev = allow_loopback and host in {"localhost", "127.0.0.1", "::1"}
    internal = explicit or local or dev
    if scheme != "https" and not internal:
        raise OutboundPolicyError("Use HTTPS, or explicitly allow this service origin")
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise OutboundPolicyError("Destination DNS lookup failed") from None
    addresses = []
    for answer in answers:
        ip = ipaddress.ip_address(answer[4][0].split("%", 1)[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if (ip.is_link_local or ip.is_multicast or ip.is_unspecified
                or (ip.is_reserved and not ip.is_loopback)
                or getattr(ip, "sixtofour", None) or getattr(ip, "teredo", None)
                or str(ip) in {"100.100.100.200", "168.63.129.16", "fd00:ec2::254"}):
            raise OutboundPolicyError("Metadata, link-local and reserved destinations are blocked")
        if not ip.is_global and not internal:
            raise OutboundPolicyError("Internal destinations require an exact outbound allowlist origin")
        if (local or dev) and not explicit and not ip.is_loopback:
            raise OutboundPolicyError("Local AI destination did not resolve to loopback")
        addresses.append(answer[4][0])
    if not addresses: raise OutboundPolicyError("Destination has no usable addresses")
    return (scheme, host, port), list(dict.fromkeys(addresses))


class Response(io.BytesIO):
    def __init__(self, body, status, headers):
        super().__init__(body)
        self.status, self.headers = status, headers


def open_request(req, *, timeout=20, max_bytes=JSON_LIMIT, purpose="generic", allow_loopback=False):
    """Bound socket IO; DNS remains subject to the OS resolver timeout."""
    if not _SLOTS.acquire(blocking=False):
        raise OutboundPolicyError("Outbound request capacity reached; retry later")
    conn = resp = watchdog = None
    deadline = time.monotonic() + max(.1, min(float(timeout), 300.0))
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0: raise TimeoutError("Outbound request deadline exceeded")
        return value
    try:
        (scheme, host, port), addresses = resolve_destination(req.full_url, purpose=purpose, allow_loopback=allow_loopback)
        cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        kwargs = {"context": ssl.create_default_context()} if scheme == "https" else {}
        conn = cls(host, port, timeout=remaining(), **kwargs)
        def connect_pinned(_address, timeout=None, source_address=None, **_kwargs):
            last_error = None
            for address in addresses:
                try:
                    sock = socket.create_connection((address, port), remaining(), source_address)
                    try:
                        sock.settimeout(remaining())
                        return sock
                    except Exception:
                        sock.close()
                        raise
                except OSError as exc: last_error = exc
            raise ConnectionError("Connection to validated destination failed") from last_error
        # Original host is retained for HTTP Host and TLS SNI/certificate checks.
        conn._create_connection = connect_pinned
        conn.connect()
        wire = conn.sock
        wire.settimeout(remaining())
        def interrupt_io():
            try: wire.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        watchdog = threading.Timer(remaining(), interrupt_io)
        watchdog.daemon = True
        watchdog.start()
        p = urllib.parse.urlsplit(req.full_url)
        path = urllib.parse.urlunsplit(("", "", p.path or "/", p.query, ""))
        headers = {key.title(): value for key, value in req.header_items()}
        if any(k.lower() in {"host", "connection", "transfer-encoding", "content-length"} for k in headers):
            raise OutboundPolicyError("Custom transport-routing headers are not allowed")
        headers["Connection"] = "close"
        conn.request(req.get_method(), path, body=req.data, headers=headers)
        wire.settimeout(remaining())
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            raise urllib.error.HTTPError("[upstream]", resp.status, "Redirects are blocked; configure the final URL", resp.headers, io.BytesIO())
        if resp.status >= 400:
            raise urllib.error.HTTPError("[upstream]", resp.status, "upstream request failed", resp.headers, io.BytesIO())
        length = resp.headers.get("Content-Length")
        if length is not None:
            try: declared = int(length)
            except ValueError: raise OutboundPolicyError("Invalid upstream response length") from None
            if declared < 0 or declared > max_bytes:
                raise OutboundPolicyError("Upstream response exceeds the byte limit")
        chunks, size = [], 0
        while True:
            sock = conn.sock or getattr(getattr(resp.fp, "raw", None), "_sock", None)
            if sock is not None: sock.settimeout(remaining())
            else: remaining()
            chunk = resp.read1(min(65536, max_bytes + 1 - size))
            if not chunk: break
            size += len(chunk)
            if size > max_bytes: raise OutboundPolicyError("Upstream response exceeds the byte limit")
            chunks.append(chunk)
        remaining()
        if length is not None and size != int(length):
            raise OutboundPolicyError("Upstream response ended before its declared length")
        return Response(b"".join(chunks), resp.status, resp.headers)
    except (urllib.error.HTTPError, OutboundPolicyError):
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise urllib.error.URLError("Outbound connection failed or timed out") from exc
    except (ValueError, UnicodeError):
        raise OutboundPolicyError("Invalid outbound request URL, headers or encoding") from None
    finally:
        if watchdog is not None: watchdog.cancel()
        try:
            if resp is not None: resp.close()
        finally:
            try:
                if conn is not None: conn.close()
            finally: _SLOTS.release()
