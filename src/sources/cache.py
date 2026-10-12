"""File cache for external lookups: cache/<key>.json with a retrieved_at timestamp."""
import json
import re
from datetime import datetime, timezone

from src.config import load_settings, resolve

# Tests point this at a temporary directory.
CACHE_DIR = resolve(load_settings().get("cache_dir", "cache"))


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path(key):
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", key):
        raise ValueError(f"invalid cache key: {key!r}")
    return CACHE_DIR / f"{key}.json"


def save(key, data):
    """Write data to cache/<key>.json and return the retrieved_at timestamp."""
    path = _path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    retrieved_at = now_iso()
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"retrieved_at": retrieved_at, "data": data}, f, ensure_ascii=False, indent=1)
    tmp.replace(path)
    return retrieved_at


def load_entry(key):
    """Return {"retrieved_at", "data"} or None if missing or unreadable."""
    try:
        with open(_path(key), encoding="utf-8") as f:
            entry = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(entry, dict) or "data" not in entry:
        return None
    return entry


def load(key):
    """Return the cached data or None."""
    entry = load_entry(key)
    return None if entry is None else entry["data"]
