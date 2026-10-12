"""CISA Known Exploited Vulnerabilities (KEV) feed client."""
from src.config import load_settings
from src.sources._fetch import fetch_json

CACHE_KEY = "kev_feed"
NOT_LISTED_NOTE = "absence from KEV does not establish safety"


def _validate(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
        raise ValueError("response is not a CISA KEV feed")


def find_entry(feed, cve_id):
    return next((v for v in feed.get("vulnerabilities", []) if v.get("cveID") == cve_id), None)


def fetch_kev_entry(cve_id, url=None, timeout=None):
    """Download the KEV feed, cache the whole feed, and return the entry for one CVE.

    Returns {"status": "live"|"cached"|"error", "source", "retrieved_at",
    "data", "unknown_fields", "error"}. data.in_kev is False (with a note)
    when the CVE is not listed.
    """
    settings = load_settings()
    url = url or settings["kev_url"]
    timeout = timeout or settings.get("timeouts", {}).get("kev_seconds", 15)

    got = fetch_json(url, CACHE_KEY, timeout, validate=_validate)
    result = {"status": got["status"], "source": url, "retrieved_at": got["retrieved_at"],
              "data": None, "unknown_fields": [], "error": got["error"]}
    feed = got["raw"]
    if feed is None:
        return result

    entry = find_entry(feed, cve_id)
    data = {
        "cve_id": cve_id,
        "in_kev": entry is not None,
        "catalog_version": feed.get("catalogVersion"),
        "catalog_date_released": feed.get("dateReleased"),
        "entry": entry,
    }
    if entry is None:
        data["note"] = NOT_LISTED_NOTE
    else:
        result["unknown_fields"] = [f"entry.{k}" for k, v in entry.items() if v is None]
    result["data"] = data
    return result
