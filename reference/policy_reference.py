"""Reference implementation of the rating policy in docs/rating_policy.md.

Purpose: let Student A check that the expected results are what the written policy
produces, and give Student C an exact specification to match in src/policy.py.
This file reads the snapshot directly; the real agent gets these facts through tools.

    python reference/policy_reference.py environment/northbridge-v1.1.json
"""
import json
import sys

RATINGS = ["Low", "Medium", "High"]

# Threat facts from inputs/CVE-2026-85880_nvd_summary.json (T1, T2)
THREAT = {
    "cve_id": "CVE-2026-85880",
    "cvss_v31": 7.8,
    "in_kev": True,
    "requires_low_priv_local_access": True,
    "fixed_builds": {  # product name prefix -> first fixed build
        "Windows Server 2016": "10.0.14393.9512",
        "Windows Server 2019": "10.0.17763.9245",
        "Windows Server 2022": "10.0.20348.5622",
        "Windows 10 Enterprise|22H2": "10.0.19045.7725",
    },
}

PRIORITY_MATRIX = {  # (data_row, exposure) -> priority
    ("pii_unprotected", "internet"): "P1", ("pii_unprotected", "intranet"): "P1", ("pii_unprotected", "internal_only"): "P2",
    ("pii_protected", "internet"): "P1", ("pii_protected", "intranet"): "P2", ("pii_protected", "internal_only"): "P3",
    ("no_pii", "internet"): "P2", ("no_pii", "intranet"): "P3", ("no_pii", "internal_only"): "P3",
}

FINAL_MATRIX = {  # (priority, severity band) -> rating
    ("P1", "Critical"): "High", ("P1", "High"): "High", ("P1", "Medium"): "Medium", ("P1", "Low"): "Medium",
    ("P2", "Critical"): "High", ("P2", "High"): "Medium", ("P2", "Medium"): "Medium", ("P2", "Low"): "Low",
    ("P3", "Critical"): "Medium", ("P3", "High"): "Low", ("P3", "Medium"): "Low", ("P3", "Low"): "Low",
}


def severity_band(score):
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def priority(asset):
    if asset.get("priority_override"):
        return "P1", f"override: {asset['priority_override']}"
    data = asset["data_classification"]
    if data in ("restricted_pii", "pii"):
        row = "pii_protected" if asset["data_protection"] == "protected" else "pii_unprotected"
    else:
        row = "no_pii"
    exposure = "internal_only" if asset["exposure"] == "isolated" else asset["exposure"]
    p = PRIORITY_MATRIX[(row, exposure)]
    return p, f"matrix: {row} x {exposure}"


def build_tuple(build):
    return tuple(int(x) for x in build.split("."))


def fixed_build_for(os_):
    for key, fixed in THREAT["fixed_builds"].items():
        name, _, version = key.partition("|")
        if os_["name"] == name and (not version or os_.get("version") == version):
            return fixed
    return None


def conflicting_build(snapshot, asset):
    """Return a build stated for this asset in evidence S08 if it differs from the asset record."""
    for ev in snapshot.get("evidence", []):
        if ev["evidence_id"] != "S08":
            continue
        for fact in ev["facts"]:
            if fact.startswith(f"{asset['asset_id']}:") and asset["os"].get("build") and asset["os"]["build"] not in fact:
                return fact
    return None


def applicability(snapshot, asset):
    os_ = asset["os"]
    fixed = fixed_build_for(os_)
    if fixed is None:
        return "Not applicable", "product not in the CVE's affected list"
    if conflicting_build(snapshot, asset):
        return "Conflict", "S08 and the asset record disagree on the build"
    if os_.get("build") is None:
        return "Unknown", "OS build unknown (decisive)"
    if build_tuple(os_["build"]) >= build_tuple(fixed):
        return "Not applicable", f"build {os_['build']} >= fixed {fixed}"
    access = asset.get("low_priv_local_access")
    if access is None:
        return "Unknown", "low-privilege local access path unknown (decisive)"
    if asset["exposure"] == "isolated" or access is False:
        return "Partial", f"vulnerable build {os_['build']} < {fixed}, but no low-privilege local access path"
    return "Confirmed", f"vulnerable build {os_['build']} < {fixed} and low-privilege local access exists"


def rate(snapshot, asset):
    appl, why = applicability(snapshot, asset)
    prio, prio_why = priority(asset)
    band = severity_band(THREAT["cvss_v31"])
    if appl in ("Unknown", "Conflict"):
        return {"applicability": appl, "priority": prio, "decision": "INSUFFICIENT_EVIDENCE",
                "rule": "decisive fact unknown or conflicting -> analyst review", "why": why}
    if appl == "Not applicable":
        return {"applicability": appl, "priority": prio, "decision": "Low",
                "rule": "gate: not applicable -> Low", "why": why}
    base = FINAL_MATRIX[(prio, band)]
    idx = RATINGS.index(base)
    steps = [f"{prio} x {band} = {base}"]
    if THREAT["in_kev"]:
        idx = min(idx + 1, 2)
        steps.append(f"KEV +1 -> {RATINGS[idx]}")
    if appl == "Partial":
        idx = max(idx - 1, 0)
        steps.append(f"Partial -1 -> {RATINGS[idx]}")
    return {"applicability": appl, "priority": prio, "decision": RATINGS[idx],
            "rule": "; ".join(steps), "why": f"{why}; {prio_why}"}


def main(path, only=None):
    snapshot = json.load(open(path))
    print(f"# {snapshot['snapshot_id']}")
    for asset in snapshot["assets"]:
        label = f"{asset['asset_id']} {asset['instance']}"
        if only and asset["asset_id"] != only:
            continue
        r = rate(snapshot, asset)
        print(f"{label:<45} {r['applicability']:<15} {r['priority']}  {r['decision']:<22} {r['rule']}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
