"""
mini-SIEM threat intelligence (IOC matching)
============================================
Matches incoming log events against a database of indicators of
compromise (IOCs) — malicious IPs, domains, URLs, and file hashes —
and raises an alert + records a match when a log touches one.

Design mirrors the forwarder: an in-memory index of enabled IOCs is
hot-reloaded from the `iocs` table every few seconds, so adding or
importing indicators takes effect without restarting the listener. The
match check runs in the ingest path using type-appropriate indexes: direct
lookups for IP/hash, extracted-domain suffix lookup for domains, and a
dependency-free Aho-Corasick multi-pattern automaton for URL substrings.
This keeps per-event work bounded as IOC collections grow.

Supported IOC types:
    ip     — exact match against source_ip, hostname, and any IPs in the message
    domain — exact/parent-domain suffix match from extracted host/domain tokens
    url    — substring match in message through one multi-pattern automaton
    hash   — md5/sha1/sha256 token match in message (hex, case-insensitive)

Matches are written to `ioc_matches` and also raise an alert through the
same Storage.insert_alert path, so they flow into correlation, the alert
feed, and AI auto-triage like any other detection.
"""

import re
import threading
import time
from datetime import datetime, timezone

IOC_TYPES = ("ip", "domain", "url", "hash")

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_HASH = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_DOMAIN = re.compile(r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9\-]{2,})+)\b", re.IGNORECASE)


def normalize_ioc(ioc_type: str, value: str) -> str:
    """Canonical form used for matching and dedupe."""
    v = (value or "").strip().lower()
    if ioc_type == "url":
        v = v.rstrip("/")
    return v




class MultiPatternMatcher:
    """Small dependency-free Aho-Corasick matcher for URL substrings.

    The automaton is rebuilt only when the IOC table reloads, so per-event URL
    matching is O(message length + matches) rather than O(number of URL IOCs).
    """

    def __init__(self, patterns=()):
        self.goto = [dict()]
        self.fail = [0]
        self.out = [[]]
        for pattern in patterns:
            pat = str(pattern or "")
            if not pat:
                continue
            state = 0
            for ch in pat:
                nxt = self.goto[state].get(ch)
                if nxt is None:
                    nxt = len(self.goto)
                    self.goto[state][ch] = nxt
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append([])
                state = nxt
            self.out[state].append(pat)
        from collections import deque
        q = deque()
        for _ch, state in self.goto[0].items():
            q.append(state)
            self.fail[state] = 0
        while q:
            r = q.popleft()
            for ch, state in self.goto[r].items():
                q.append(state)
                f = self.fail[r]
                while f and ch not in self.goto[f]:
                    f = self.fail[f]
                self.fail[state] = self.goto[f].get(ch, 0)
                self.out[state].extend(self.out[self.fail[state]])

    def find(self, text):
        state = 0
        seen = set()
        for ch in str(text or ""):
            while state and ch not in self.goto[state]:
                state = self.fail[state]
            state = self.goto[state].get(ch, 0)
            for pattern in self.out[state]:
                if pattern not in seen:
                    seen.add(pattern)
                    yield pattern


def _domain_suffixes(value):
    """Yield host/domain then parent suffixes, excluding bare TLDs."""
    host = str(value or "").strip().lower().strip(".")
    if not host:
        return
    labels = [p for p in host.split(".") if p]
    for i in range(max(0, len(labels) - 1)):
        suffix = ".".join(labels[i:])
        if "." in suffix:
            yield suffix

def guess_type(value: str) -> str:
    """Best-effort classification when a feed doesn't specify the type."""
    v = (value or "").strip()
    if _IPV4.fullmatch(v):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", v):
        return "hash"
    if v.lower().startswith(("http://", "https://")) or "/" in v:
        return "url"
    return "domain"


class IOCMatcher:
    """Hot-reloaded IOC index + per-event matching."""

    def __init__(self, storage, reload_interval: int = 5):
        self.storage = storage
        self.reload_interval = reload_interval
        self._lock = threading.Lock()
        self._ips = {}      # value_norm -> ioc dict
        self._domains = {}
        self._urls = {}
        self._url_matcher = MultiPatternMatcher()
        self._hashes = {}
        self._count = 0
        self._stop = threading.Event()
        self._reload()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ioc-reload")
        self._thread.start()

    # -- reload ------------------------------------------------------------

    def _loop(self):
        while not self._stop.wait(self.reload_interval):
            try:
                self._reload()
            except Exception as exc:
                print(f"[ti] IOC reload failed: {exc}")

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def _reload(self):
        with self.storage.lock:
            rows = [dict(r) for r in self.storage.conn.execute(
                """SELECT id, ioc_type, value, value_norm, threat, source, severity
                   FROM iocs WHERE enabled = 1""").fetchall()]
        ips, domains, urls, hashes = {}, {}, {}, {}
        for r in rows:
            t = r["ioc_type"]
            key = r["value_norm"]
            if t == "ip":
                ips[key] = r
            elif t == "domain":
                domains[key] = r
            elif t == "url":
                urls[key] = r
            elif t == "hash":
                hashes[key] = r
        url_matcher = MultiPatternMatcher(urls.keys())
        with self._lock:
            self._ips, self._domains, self._urls, self._hashes = ips, domains, urls, hashes
            self._url_matcher = url_matcher
            self._count = len(rows)

    def count(self):
        with self._lock:
            return self._count

    # -- matching ----------------------------------------------------------

    def check(self, event: dict):
        """Return a list of match dicts (usually 0 or 1) for one event."""
        with self._lock:
            if self._count == 0:
                return []
            ips, domains, urls, hashes = self._ips, self._domains, self._urls, self._hashes
            url_matcher = self._url_matcher

        msg = event.get("message", "") or ""
        msg_l = msg.lower()
        matches = []
        seen = set()

        # IP: check source_ip, hostname, and IPs in the message
        candidate_ips = set()
        for f in (event.get("source_ip"), event.get("hostname")):
            if f:
                candidate_ips.add(str(f).strip().lower())
        for m in _IPV4.findall(msg):
            candidate_ips.add(m.lower())
        for ip in candidate_ips:
            if ip in ips and ("ip", ip) not in seen:
                seen.add(("ip", ip)); matches.append(ips[ip])

        # hash: tokens in the message
        for h in _HASH.findall(msg):
            hn = h.lower()
            if hn in hashes and ("hash", hn) not in seen:
                seen.add(("hash", hn)); matches.append(hashes[hn])

        # URL: dependency-free Aho-Corasick multi-pattern scan. This preserves
        # the historical substring semantics while avoiding one `in` scan per
        # configured URL IOC.
        for key in url_matcher.find(msg_l):
            ioc = urls.get(key)
            if ioc is not None and ("url", key) not in seen:
                seen.add(("url", key)); matches.append(ioc)

        # Domain: extract domain-shaped tokens once, then exact/suffix lookup.
        # `evil.example` therefore matches `sub.evil.example`, but an IOC never
        # matches arbitrary prose just because its letters occur inside a word.
        domain_candidates = set(_DOMAIN.findall(msg_l))
        host_l = (event.get("hostname") or "").lower().strip(".")
        if host_l and "." in host_l:
            domain_candidates.add(host_l)
        for candidate in domain_candidates:
            for key in _domain_suffixes(candidate):
                ioc = domains.get(key)
                if ioc is not None and ("domain", key) not in seen:
                    seen.add(("domain", key)); matches.append(ioc)

        return matches

    def process(self, log_id: int, event: dict):
        """Check an event; on match, record it and raise an alert.
        Returns the number of matches."""
        matches = self.check(event)
        if not matches:
            return 0
        for ioc in matches:
            self._record(log_id, event, ioc)
        return len(matches)

    def _record(self, log_id: int, event: dict, ioc: dict):
        threat = ioc.get("threat") or ioc.get("source") or "IOC hit"
        with self.storage.lock:
            try:
                self.storage.conn.execute(
                    """INSERT INTO ioc_matches
                       (matched_at, ioc_id, ioc_type, ioc_value, threat, log_id,
                        source_ip, hostname, message)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (datetime.now(timezone.utc).isoformat(), ioc.get("id"),
                     ioc.get("ioc_type"), ioc.get("value"), threat, log_id,
                     event.get("source_ip"), event.get("hostname"),
                     (event.get("message") or "")[:500]))
                self.storage.commit_locked()
            except Exception:
                self.storage.rollback_locked()
                raise
        self.storage.insert_alert(
            rule_name="threat_intel_match",
            severity=ioc.get("severity") or "warning",
            source_ip=event.get("source_ip") or "",
            description=f"IOC match ({ioc.get('ioc_type')}): {ioc.get('value')} — {threat}",
            log_ids=[log_id])
        print(f"  [IOC] {ioc.get('ioc_type')} {ioc.get('value')} matched log #{log_id} — {threat}")


# --------------------------------------------------------------------------
# Import helpers (used by the dashboard's feed importer)
# --------------------------------------------------------------------------

def parse_feed_text(text: str, default_type: str = "", default_threat: str = "",
                     source: str = "manual", severity: str = "warning"):
    """Parse pasted/uploaded indicator text into IOC rows. Accepts one
    indicator per line; lines starting with # are comments. Optional CSV
    form 'value,type,threat' is supported per line."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        value = parts[0]
        ioc_type = (parts[1] if len(parts) > 1 and parts[1] else default_type) or guess_type(value)
        threat = (parts[2] if len(parts) > 2 and parts[2] else default_threat)
        if ioc_type not in IOC_TYPES:
            ioc_type = guess_type(value)
        out.append({
            "ioc_type": ioc_type,
            "value": value,
            "value_norm": normalize_ioc(ioc_type, value),
            "threat": threat,
            "source": source,
            "severity": severity,
        })
    return out
