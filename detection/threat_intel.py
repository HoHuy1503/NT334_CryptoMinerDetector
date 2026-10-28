"""Opt-in, hash-only MalwareBazaar lookups for already suspicious executables.

No files are uploaded or downloaded. Only a SHA-256 digest is sent, and only
when an API key is configured by the user.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_URL = "https://mb-api.abuse.ch/api/v1/"
REQUEST_TIMEOUT_SECONDS = 5
NEGATIVE_CACHE_SECONDS = 3600
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="threat-intel")


def _hash_and_lookup(executable: str, api_key: str) -> dict[str, Any]:
    path = Path(executable)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {"status": "unavailable", "reason": "executable_unreadable"}
    sha256 = digest.hexdigest()

    body = urlencode({"query": "get_info", "hash": sha256}).encode("ascii")
    request = Request(API_URL, data=body, headers={
        "Auth-Key": api_key,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "CryptoMinerDetector/1.0",
    }, method="POST")
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except (OSError, URLError, TimeoutError, ValueError):
        return {"status": "unavailable", "sha256": sha256, "reason": "lookup_failed_or_timeout"}

    query_status = payload.get("query_status") if isinstance(payload, dict) else None
    if query_status == "hash_not_found":
        return {"status": "not_found", "sha256": sha256}
    data = payload.get("data", []) if isinstance(payload, dict) else []
    if query_status == "ok" and isinstance(data, list) and data and isinstance(data[0], dict):
        record = data[0]
        return {
            "status": "known_malware",
            "sha256": sha256,
            "signature": record.get("signature"),
            "first_seen": record.get("first_seen"),
            "file_type": record.get("file_type"),
        }
    return {"status": "unavailable", "sha256": sha256, "reason": str(query_status or "unexpected_response")[:80]}


class ThreatIntelClient:
    """Background hash lookup client; no network access without an explicit key."""

    def __init__(self, api_key: str | None):
        self.api_key = api_key.strip() if api_key and api_key.strip() else None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def enabled(self) -> bool:
        return self.api_key is not None

    def enrich_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        if not self.api_key:
            return alert
        executable = alert.get("executable_path")
        if not isinstance(executable, str) or not executable:
            return alert
        try:
            stat = os.stat(executable)
            fingerprint = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return alert

        cached = self._cache.get(executable.casefold())
        now = time.monotonic()
        if cached is None or cached["fingerprint"] != fingerprint:
            future = _EXECUTOR.submit(_hash_and_lookup, executable, self.api_key)
            self._cache[executable.casefold()] = {
                "fingerprint": fingerprint, "submitted_at": now, "future": future,
            }
            return alert

        future = cached["future"]
        if not future.done():
            return alert
        try:
            result = future.result()
        except Exception:
            return alert
        if result.get("status") != "known_malware" and now - cached["submitted_at"] >= NEGATIVE_CACHE_SECONDS:
            future = _EXECUTOR.submit(_hash_and_lookup, executable, self.api_key)
            self._cache[executable.casefold()] = {
                "fingerprint": fingerprint, "submitted_at": now, "future": future,
            }
            return alert
        if result.get("status") != "known_malware":
            return alert

        enriched = dict(alert)
        indicators = list(alert.get("indicators", []))
        if not any(item.get("rule_id") == "THREAT_INTEL_HASH_MATCH" for item in indicators):
            indicators.append({
                "rule_id": "THREAT_INTEL_HASH_MATCH",
                "points": 60,
                "details": {key: result.get(key) for key in ("sha256", "signature", "first_seen", "file_type")},
            })
        enriched["indicators"] = indicators
        enriched["score"] = min(100, int(alert.get("score", 0)) + 60)
        enriched["severity"] = "high"
        return enriched
