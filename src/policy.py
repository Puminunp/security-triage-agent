"""Rating policy (docs/rating_policy.md) as code. The model never calls this and never
chooses a rating: the agent hands it validated facts and it returns the decision.

    rate(asset_facts, threat_facts) -> {"applicability", "priority", "severity_band",
                                        "decision", "rule", "why", ...}

Must give the same applicability, priority and decision as reference/policy_reference.py
on the base snapshot and every variant (tests/test_policy.py checks this).
"""

RATINGS = ["Low", "Medium", "High"]
INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

# Section 3: (data row, exposure) -> machine priority
PRIORITY_MATRIX = {
    ("pii_unprotected", "internet"): "P1", ("pii_unprotected", "intranet"): "P1",
    ("pii_unprotected", "internal_only"): "P2",
    ("pii_protected", "internet"): "P1", ("pii_protected", "intranet"): "P2",
    ("pii_protected", "internal_only"): "P3",
    ("no_pii", "internet"): "P2", ("no_pii", "intranet"): "P3", ("no_pii", "internal_only"): "P3",
}

# Section 5: (priority, severity band) -> rating before modifiers
FINAL_MATRIX = {
    ("P1", "Critical"): "High", ("P1", "High"): "High", ("P1", "Medium"): "Medium", ("P1", "Low"): "Medium",
    ("P2", "Critical"): "High", ("P2", "High"): "Medium", ("P2", "Medium"): "Medium", ("P2", "Low"): "Low",
    ("P3", "Critical"): "Medium", ("P3", "High"): "Low", ("P3", "Medium"): "Low", ("P3", "Low"): "Low",
}

PII_CLASSES = ("restricted_pii", "pii")
EXPOSURES = ("internet", "intranet", "internal_only", "isolated")


def severity_band(score):
    """Section 4: CVSS v3.1 base score -> band, or None when no score exists."""
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return None


def build_tuple(build):
    """'10.0.14393.9339' -> (10, 0, 14393, 9339). Builds are compared part by part."""
    return tuple(int(x) for x in build.split("."))


def priority(asset):
    """Section 3: machine priority from data x exposure, with P1 overrides.

    Returns (priority or None, reason). None means a field the matrix needs is
    unknown; the policy does not say how to rate that, so the caller treats it as
    insufficient evidence instead of guessing.
    """
    if asset.get("priority_override"):
        return "P1", f"override: {asset['priority_override']}"
    data = asset.get("data_classification")
    exposure = asset.get("exposure")
    if data is None or exposure not in EXPOSURES:
        return None, f"priority unknown: data_classification={data!r}, exposure={exposure!r}"
    if data in PII_CLASSES:
        # Unknown protection counts as "without protection" (section 3).
        row = "pii_protected" if asset.get("data_protection") == "protected" else "pii_unprotected"
    else:
        row = "no_pii"
    column = "internal_only" if exposure == "isolated" else exposure
    return PRIORITY_MATRIX[(row, column)], f"matrix: {row} x {column}"


def applicability(asset):
    """Section 2: the applicability gate.

    asset needs: affected (True/False/None), fixed_build, os_build,
    low_priv_local_access, exposure, conflicts (list).
    Order matches reference/policy_reference.py.
    """
    if asset.get("affected") is False:
        return "Not applicable", "product not in the CVE's affected list"
    if asset.get("affected") is None:
        return "Unknown", "affected-product status unknown (decisive): " + (
            asset.get("affected_reason") or "no affected-products list available")
    fixed = asset.get("fixed_build")
    if fixed is None:
        return "Unknown", "fixed build unknown (decisive): " + (
            asset.get("fixed_build_reason") or "no fixed build from NVD")
    if asset.get("conflicts"):
        return "Conflict", "sources disagree on a decisive fact: " + "; ".join(asset["conflicts"])
    build = asset.get("os_build")
    if build is None:
        return "Unknown", "OS build unknown (decisive)"
    if build_tuple(build) >= build_tuple(fixed):
        return "Not applicable", f"build {build} >= fixed {fixed}"
    access = asset.get("low_priv_local_access")
    if access is None:
        return "Unknown", "low-privilege local access path unknown (decisive)"
    if asset.get("exposure") == "isolated" or access is False:
        return "Partial", (f"vulnerable build {build} < {fixed}, but no low-privilege local "
                           f"access path (exposure={asset.get('exposure')}, "
                           f"low_priv_local_access={access})")
    return "Confirmed", f"vulnerable build {build} < {fixed} and low-privilege local access exists"


def rate(asset, threat):
    """Apply steps 1-5. threat needs: cvss_score, in_kev (True/False/None)."""
    appl, why = applicability(asset)
    prio, prio_why = priority(asset)
    band = severity_band(threat.get("cvss_score"))
    out = {"applicability": appl, "applicability_reason": why,
           "priority": prio, "priority_reason": prio_why, "severity_band": band,
           "kev_modifier": None, "partial_modifier": None}

    if appl in ("Unknown", "Conflict"):
        return {**out, "decision": INSUFFICIENT,
                "rule": "gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE "
                        "(analyst review)"}
    if appl == "Not applicable":
        return {**out, "decision": "Low", "rule": "gate: not applicable -> Low"}
    if band is None:
        return {**out, "decision": INSUFFICIENT,
                "rule": "severity unknown (no CVSS score from any source) -> INSUFFICIENT_EVIDENCE"}
    if prio is None:
        return {**out, "decision": INSUFFICIENT,
                "rule": "machine priority unknown -> INSUFFICIENT_EVIDENCE (analyst review)"}

    base = FINAL_MATRIX[(prio, band)]
    idx = RATINGS.index(base)
    steps = [f"{prio} x {band} = {base}"]
    if threat.get("in_kev") is True:
        idx = min(idx + 1, len(RATINGS) - 1)
        steps.append(f"KEV +1 -> {RATINGS[idx]}")
        out["kev_modifier"] = "+1"
    elif threat.get("in_kev") is None:
        steps.append("KEV status unknown, no modifier applied")
    if appl == "Partial":
        idx = max(idx - 1, 0)
        steps.append(f"Partial -1 -> {RATINGS[idx]}")
        out["partial_modifier"] = "-1"
    return {**out, "decision": RATINGS[idx], "rule": "; ".join(steps)}


def confidence(result, decisive_sources, cached_sources, kev_unknown=False):
    """Section 7. Reported next to the rating; never changes it.

    decisive_sources: evidence IDs / source IDs the decisive facts came from
    (e.g. ["T1", "S08", "S07"]). cached_sources: external sources that fell
    back to the cache.
    """
    if result["decision"] == INSUFFICIENT:
        return None, "no rating, so no confidence level; see the applicability reason"
    reasons = []
    level = "High"
    simulated = sorted(s for s in decisive_sources if s in ("S07", "S08"))
    if simulated:
        level = "Medium"
        reasons.append(f"decisive facts rely on group-simulated evidence {', '.join(simulated)}")
    if cached_sources:
        level = "Medium"
        reasons.append(f"cached fallback used for {', '.join(sorted(cached_sources))}")
    if kev_unknown:
        level = "Low"
        reasons.append("KEV status unknown; the rating could be one level higher")
    if not reasons:
        reasons.append("all decisive facts from live/cached external sources or original "
                       "scenario evidence (S01-S06), no conflicts")
    return level, "; ".join(reasons)
