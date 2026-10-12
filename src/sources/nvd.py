"""NVD CVE API 2.0 client."""
import os

from dotenv import load_dotenv

from src.config import REPO_ROOT, load_settings
from src.sources._fetch import fetch_json

load_dotenv(REPO_ROOT / ".env")


def cache_key(cve_id):
    return f"nvd_{cve_id}"


def _validate(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
        raise ValueError("response is not an NVD CVE API 2.0 document")


def _product_from_cpe(criteria):
    """cpe:2.3:o:microsoft:windows_server_2012:r2:... -> 'microsoft windows_server_2012 r2'."""
    parts = criteria.split(":")
    if len(parts) < 6:
        return criteria
    name = f"{parts[3]} {parts[4]}"
    if parts[5] not in ("*", "-"):
        name += f" {parts[5]}"
    return name


def _cvss_v31(metrics):
    """NVD's own score (type Primary) if present, else the CNA score (type Secondary)."""
    entries = metrics.get("cvssMetricV31") or []
    for wanted, label in (("Primary", "nvd_primary"), ("Secondary", "cna_secondary")):
        for m in entries:
            if m.get("type") == wanted:
                data = m.get("cvssData", {})
                return {
                    "base_score": data.get("baseScore"),
                    "base_severity": data.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                    "source": m.get("source"),
                    "type": m.get("type"),
                    "score_used": label,
                }
    return None


def parse(raw, cve_id):
    """Pick the fields the agent needs out of a raw NVD response.

    Returns (data, unknown_fields), or (None, []) if the CVE is not in the response.
    Missing fields stay None and are listed in unknown_fields.
    """
    cve = next((v["cve"] for v in raw.get("vulnerabilities", [])
                if v.get("cve", {}).get("id") == cve_id), None)
    if cve is None:
        return None, []

    description = next((d.get("value") for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"), None)

    cwe = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value") and d["value"] not in cwe:
                cwe.append(d["value"])

    # One row per CPE match, exactly as NVD lists them.
    affected = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                affected.append({
                    "product": _product_from_cpe(m.get("criteria", "")),
                    "cpe": m.get("criteria"),
                    "vulnerable": m.get("vulnerable"),
                    "versionStartIncluding": m.get("versionStartIncluding"),
                    "versionEndExcluding": m.get("versionEndExcluding"),
                })

    # Vendor (CNA) affected-version data, when NVD passes it through.
    cna_affected = []
    for block in cve.get("affected", []):
        for item in block.get("affectedData", []):
            for v in item.get("versions", []):
                cna_affected.append({
                    "source": block.get("source"),
                    "product": item.get("product"),
                    "status": v.get("status"),
                    "version_start": v.get("version"),
                    "lessThan": v.get("lessThan"),
                })

    data = {
        "cve_id": cve.get("id"),
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_v31": _cvss_v31(cve.get("metrics", {})),
        "cwe": cwe,
        "kev": {
            "in_kev": cve.get("cisaExploitAdd") is not None,
            "cisaExploitAdd": cve.get("cisaExploitAdd"),
            "cisaActionDue": cve.get("cisaActionDue"),
            "cisaRequiredAction": cve.get("cisaRequiredAction"),
        },
        "affected_products": affected,
        "cna_affected": cna_affected,
        "references": [{"url": r.get("url"), "tags": r.get("tags", [])}
                       for r in cve.get("references", [])],
    }

    unknown = [k for k in ("description", "published", "last_modified", "cvss_v31")
               if data[k] is None]
    if not cwe:
        unknown.append("cwe")
    if not affected:
        unknown.append("affected_products")
    for i, row in enumerate(affected):
        if row["versionEndExcluding"] is None:
            unknown.append(f"affected_products[{i}].versionEndExcluding")
    return data, unknown


def fetch_cve(cve_id, base_url=None, timeout=None):
    """Look up one CVE in NVD.

    Returns {"status": "live"|"cached"|"error"|"not_found", "source",
    "retrieved_at", "data", "unknown_fields", "error"}.
    """
    settings = load_settings()
    base_url = base_url or settings["nvd_base_url"]
    timeout = timeout or settings.get("timeouts", {}).get("nvd_seconds", 15)
    source = f"{base_url}?cveId={cve_id}"

    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else None

    got = fetch_json(base_url, cache_key(cve_id), timeout,
                     params={"cveId": cve_id}, headers=headers, validate=_validate)
    result = {"status": got["status"], "source": source, "retrieved_at": got["retrieved_at"],
              "data": None, "unknown_fields": [], "error": got["error"]}
    if got["raw"] is None:
        return result

    data, unknown = parse(got["raw"], cve_id)
    if data is None:
        result["status"] = "not_found"
        result["data"] = {"cve_id": cve_id,
                          "note": "NVD has no record for this CVE ID; this does not establish safety"}
        return result
    result["data"] = data
    result["unknown_fields"] = unknown
    return result
