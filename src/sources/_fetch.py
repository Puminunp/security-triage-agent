"""Shared download logic: try, retry once, then fall back to the cache."""
import time

import requests

from src.config import load_settings
from src.sources import cache


def fetch_json(url, cache_key, timeout, params=None, headers=None, validate=None):
    """Download JSON and cache it.

    Returns {"status": "live"|"cached"|"error", "raw", "retrieved_at", "error"}.
    "cached" keeps the reason the live call failed in "error". Nothing is
    invented: with no live response and no cache, "raw" is None.
    """
    settings = load_settings()
    retries = int(settings.get("retries", 1))
    wait = float(settings.get("retry_wait_seconds", 0))

    reason = None
    for attempt in range(retries + 1):
        if attempt:
            time.sleep(wait)
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            resp.raise_for_status()
            raw = resp.json()
            if validate:
                validate(raw)
        except (requests.RequestException, ValueError) as exc:
            reason = f"{type(exc).__name__}: {exc}"
            continue
        retrieved_at = cache.save(cache_key, raw)
        return {"status": "live", "raw": raw, "retrieved_at": retrieved_at, "error": None}

    reason = f"lookup failed after {retries + 1} attempts ({reason})"
    entry = cache.load_entry(cache_key)
    if entry is not None:
        return {"status": "cached", "raw": entry["data"],
                "retrieved_at": entry.get("retrieved_at"), "error": reason}
    return {"status": "error", "raw": None, "retrieved_at": None,
            "error": f"{reason}; no cached copy"}
