"""Lookups against the Northbridge environment snapshot (simulated data).

The snapshot path comes from config/settings.yaml (environment_snapshot); every
function also takes snapshot_path so tests can load the variant files.

Every function returns:
    {"status": "ok"|"not_found"|"error", "source_mode": "simulated",
     "snapshot_id", "locator", "data", "unknown_fields", "note", "error"}
Stored values are returned unchanged. A null stays null and its path is listed
in unknown_fields.
"""
import json
import re
from pathlib import Path

from src.config import load_settings, resolve

SOURCE_MODE = "simulated"
NO_MATCH_NOTE = "no match does not prove absence; only check_absence can"


def _load(snapshot_path):
    path = resolve(snapshot_path or load_settings()["environment_snapshot"])
    with open(path, encoding="utf-8") as f:
        return json.load(f), Path(path).name


def _result(status, snap=None, filename=None, locator=None, data=None,
            unknown_fields=None, note=None, error=None):
    return {
        "status": status,
        "source_mode": SOURCE_MODE,
        "snapshot_id": snap.get("snapshot_id") if snap else None,
        "locator": locator or filename,
        "data": data,
        "unknown_fields": unknown_fields or [],
        "note": note,
        "error": error,
    }


def _open(snapshot_path, value, name):
    """Validate a text argument and load the snapshot.

    Returns (snap, filename, cleaned_value, None) or (None, None, None, error_result).
    """
    if not isinstance(value, str) or not value.strip():
        return None, None, None, _result("error", error=f"{name} must be a non-empty string")
    try:
        snap, filename = _load(snapshot_path)
    except (OSError, ValueError, KeyError) as exc:
        return None, None, None, _result(
            "error", error=f"cannot read environment snapshot: {type(exc).__name__}: {exc}")
    return snap, filename, value.strip(), None


def _null_paths(value, prefix=""):
    """Paths of every null inside value, e.g. ['os.build', 'config.encryption_at_rest']."""
    paths = []
    if value is None:
        paths.append(prefix)
    elif isinstance(value, dict):
        for k, v in value.items():
            paths += _null_paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            paths += _null_paths(v, f"{prefix}[{i}]")
    return paths


def _hostnames(instance):
    """'DC01-DC04' -> {'DC01'..'DC04'}; 'CM01, CMDP01' -> {'CM01', 'CMDP01'}."""
    names = set()
    for part in instance.split(","):
        part = part.strip().upper()
        m = re.fullmatch(r"([A-Z-]+?)(\d+)-([A-Z-]+?)(\d+)", part)
        if m and m.group(1) == m.group(3) and int(m.group(2)) <= int(m.group(4)):
            width = len(m.group(2))
            for n in range(int(m.group(2)), int(m.group(4)) + 1):
                names.add(f"{m.group(1)}{n:0{width}d}")
        else:
            names.add(part)
    return names


def _asset_matches(indexed_assets, filename):
    """Build the matches list, the combined locator and the qualified unknown_fields."""
    matches, unknown = [], []
    for i, asset in indexed_assets:
        nulls = _null_paths(asset)
        matches.append({"locator": f"{filename}#assets[{i}]",
                        "unknown_fields": nulls,
                        "asset": asset})
        unknown += [f"assets[{i}].{p}" for p in nulls]
    locator = f"{filename}#" + ",".join(f"assets[{i}]" for i, _ in indexed_assets)
    return matches, locator, unknown


def get_asset(asset_id_or_instance, snapshot_path=None):
    """Return the asset record(s) for an asset ID (W15), instance (FINLEG01-FINLEG02)
    or single hostname (FINLEG01). One asset ID can cover several records (W02, E02)."""
    snap, filename, query, err = _open(snapshot_path, asset_id_or_instance, "asset_id_or_instance")
    if err:
        return err
    q = query.upper()
    assets = list(enumerate(snap.get("assets", [])))
    found = [(i, a) for i, a in assets if str(a.get("asset_id", "")).upper() == q]
    if not found:
        found = [(i, a) for i, a in assets if str(a.get("instance", "")).upper() == q]
    if not found:
        found = [(i, a) for i, a in assets if q in _hostnames(str(a.get("instance", "")))]
    if not found:
        return _result("not_found", snap, filename, locator=f"{filename}#assets",
                       data={"query": query, "matches": []}, note=NO_MATCH_NOTE)
    matches, locator, unknown = _asset_matches(found, filename)
    return _result("ok", snap, filename, locator=locator,
                   data={"query": query, "matches": matches}, unknown_fields=unknown)


def search_assets(text, limit=10, snapshot_path=None):
    """Case-insensitive text search over every field of every asset record."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return _result("error", error="limit must be an integer from 1 to 50")
    snap, filename, query, err = _open(snapshot_path, text, "text")
    if err:
        return err
    q = query.lower()
    found = [(i, a) for i, a in enumerate(snap.get("assets", []))
             if q in json.dumps(a, ensure_ascii=False).lower()]
    if not found:
        return _result("not_found", snap, filename, locator=f"{filename}#assets",
                       data={"query": query, "total_matches": 0, "matches": []},
                       note=NO_MATCH_NOTE)
    matches, locator, unknown = _asset_matches(found[:limit], filename)
    note = None
    if len(found) > limit:
        note = f"showing {limit} of {len(found)} matches; raise limit or narrow the text"
    return _result("ok", snap, filename, locator=locator,
                   data={"query": query, "total_matches": len(found), "matches": matches},
                   unknown_fields=unknown, note=note)


def get_evidence(evidence_id, snapshot_path=None):
    """Return one evidence record (S01-S08) exactly as stored."""
    snap, filename, query, err = _open(snapshot_path, evidence_id, "evidence_id")
    if err:
        return err
    for i, ev in enumerate(snap.get("evidence", [])):
        if str(ev.get("evidence_id", "")).upper() == query.upper():
            return _result("ok", snap, filename, locator=f"{filename}#evidence[{i}]",
                           data={"query": query, "evidence": ev},
                           unknown_fields=_null_paths(ev))
    return _result("not_found", snap, filename, locator=f"{filename}#evidence",
                   data={"query": query, "evidence": None}, note=NO_MATCH_NOTE)


def get_flows(zone, snapshot_path=None):
    """Return the network flows into and out of a zone, plus the default policy."""
    snap, filename, query, err = _open(snapshot_path, zone, "zone")
    if err:
        return err
    q = query.upper()
    flows = list(enumerate(snap.get("flows", [])))
    inbound = [(i, f) for i, f in flows if str(f.get("to", "")).upper() == q]
    outbound = [(i, f) for i, f in flows if str(f.get("from", "")).upper() == q]
    zone_record = next((z for z in snap.get("zones", [])
                        if str(z.get("zone_id", "")).upper() == q), None)
    data = {"query": query, "zone": zone_record,
            "inbound": [f for _, f in inbound], "outbound": [f for _, f in outbound],
            "default_policy": snap.get("default_policy")}
    if zone_record is None and not inbound and not outbound:
        return _result("not_found", snap, filename, locator=f"{filename}#flows",
                       data=data, note=NO_MATCH_NOTE)
    indexes = sorted({i for i, _ in inbound + outbound})
    locator = f"{filename}#" + (",".join(f"flows[{i}]" for i in indexes) or "flows")
    note = None
    if not indexes:
        note = "zone exists but no flow is listed for it; the default policy applies"
    return _result("ok", snap, filename, locator=locator, data=data,
                   unknown_fields=_null_paths({"inbound": data["inbound"],
                                               "outbound": data["outbound"]}),
                   note=note)


def check_absence(product, snapshot_path=None):
    """Say whether the snapshot documents that a product is NOT used at Northbridge.

    data.absent is true only for an exact (case-insensitive) match on the
    absences list. Otherwise it is null: not being on the list does not show
    the product is present or absent.
    """
    snap, filename, query, err = _open(snapshot_path, product, "product")
    if err:
        return err
    q = " ".join(query.lower().split())
    absences = snap.get("absences", [])
    for i, entry in enumerate(absences):
        if " ".join(str(entry).lower().split()) == q:
            return _result("ok", snap, filename, locator=f"{filename}#absences[{i}]",
                           data={"query": query, "absent": True, "matched_entry": entry})
    similar = [e for e in absences if q in str(e).lower() or str(e).lower() in q]
    return _result("not_found", snap, filename, locator=f"{filename}#absences",
                   data={"query": query, "absent": None, "matched_entry": None,
                         "similar_entries": similar},
                   unknown_fields=["absent"],
                   note="product is not on the documented absences list; this does not show "
                        "it is present or absent. Use get_asset or search_assets to look for it")


def get_business_service(name, snapshot_path=None):
    """Return one business service record (consequence, RTO, RPO)."""
    snap, filename, query, err = _open(snapshot_path, name, "name")
    if err:
        return err
    for i, svc in enumerate(snap.get("business_services", [])):
        if str(svc.get("service", "")).lower() == query.lower():
            return _result("ok", snap, filename, locator=f"{filename}#business_services[{i}]",
                           data={"query": query, "business_service": svc},
                           unknown_fields=_null_paths(svc))
    return _result("not_found", snap, filename, locator=f"{filename}#business_services",
                   data={"query": query, "business_service": None,
                         "available": [s.get("service") for s in snap.get("business_services", [])]},
                   note=NO_MATCH_NOTE)
