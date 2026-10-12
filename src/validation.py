"""Output validation: check the model's submitted facts against the tool results.

The model extracts facts and submits them with submit_findings. Nothing it
submits is trusted. For every finding this module checks each fact against the
evidence ledger (what the tools actually returned in this run) and returns
either errors (sent back to the model to fix) or validated facts taken from the
tool data, which the policy code then rates.
"""
import re

from src.policy import build_tuple

VENDOR = "microsoft "


# --- deterministic helpers ---------------------------------------------------

def cpe_label_for_os(os_):
    """Map an asset's OS to the NVD product label lookup_vulnerability uses
    (without the 'microsoft ' prefix), e.g.
      Windows Server 2016 / 1607   -> windows_server_2016
      Windows 10 Enterprise / 22H2 -> windows_10_22h2
      Windows 11 Enterprise / 24H2 -> windows_11_24h2
    Returns None for non-Windows products.
    """
    name = str((os_ or {}).get("name") or "").lower()
    version = str((os_ or {}).get("version") or "").lower()
    m = re.match(r"windows server (\d{4})( r2)?", name)
    if m:
        return f"windows_server_{m.group(1)}" + (" r2" if m.group(2) else "")
    m = re.match(r"windows (10|11)\b", name)
    if m:
        return f"windows_{m.group(1)}_{version}" if version else f"windows_{m.group(1)}"
    return None


def normalize_label(label):
    if label is None:
        return None
    label = " ".join(str(label).lower().split())
    return label[len(VENDOR):] if label.startswith(VENDOR) else label


def nvd_index(nvd_data):
    """{label: {"fixed_builds": set()}} for every vulnerable CPE row in the NVD result."""
    index = {}
    for row in (nvd_data or {}).get("affected_products", []):
        if row.get("vulnerable") is False:
            continue
        label = normalize_label(row.get("product"))
        entry = index.setdefault(label, {"fixed_builds": set()})
        if row.get("versionEndExcluding"):
            entry["fixed_builds"].add(row["versionEndExcluding"])
    return index


def detect_conflicts(record, evidence_records):
    """Evidence facts about this asset that state a different build than the asset record.

    Same rule as reference/policy_reference.py: a fact that starts with
    '<asset_id>:' and does not contain the record's build. Only evidence the
    agent actually fetched is checked.
    """
    build = (record.get("os") or {}).get("build")
    if not build:
        return []
    conflicts = []
    for ev_id, ev in sorted(evidence_records.items()):
        for fact in ev["record"].get("facts", []):
            if fact.startswith(f"{record.get('asset_id')}:") and build not in fact:
                conflicts.append({"evidence_id": ev_id, "ref": ev["ref"],
                                  "detail": f"{ev_id} says '{fact}' but the asset record says "
                                            f"build {build}"})
    return conflicts


def _query_covers(query, label):
    q = "_".join(str(query).lower().replace("microsoft", "").split())
    return bool(q) and (q in label.replace(" ", "_"))


# --- the validator ---------------------------------------------------------

def validate(submission, ledger):
    """Return (validated, errors).

    validated: {"findings": [...facts from tool data...], "coverage": {...},
                "nvd_available": bool}
    errors: list of strings for the model. Empty means the submission passed.
    """
    errors = []
    if not isinstance(submission, dict) or not isinstance(submission.get("findings"), list):
        return None, ["submit_findings needs an object with a 'findings' list"]

    if not ledger.nvd_attempts:
        errors.append("call lookup_vulnerability before submitting")
    if not ledger.kev_attempts:
        errors.append("call lookup_kev before submitting")

    nvd_data = ledger.nvd["result"]["data"] if ledger.nvd else None
    index = nvd_index(nvd_data) if nvd_data else None
    nvd_error = None
    if ledger.nvd_attempts and not ledger.nvd:
        nvd_error = ledger.nvd_attempts[-1]["result"].get("error") or "lookup failed"

    findings, seen = [], set()
    for i, f in enumerate(submission["findings"]):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where}: must be an object")
            continue
        loc = f.get("locator")
        hit = ledger.assets.get(loc)
        if hit is None:
            errors.append(f"{where}: locator {loc!r} was not returned by any lookup_environment "
                          f"call in this run; copy the locator from a get_asset/search_assets match")
            continue
        if loc in seen:
            errors.append(f"{where}: duplicate locator {loc}")
            continue
        seen.add(loc)
        rec = hit["record"]
        os_ = rec.get("os") or {}
        where = f"{where} ({rec.get('asset_id')} {rec.get('instance')})"
        ferr = []

        if f.get("asset_id") != rec.get("asset_id") or f.get("instance") != rec.get("instance"):
            ferr.append(f"{where}: asset_id/instance do not match the record at {loc}")
        if f.get("os_build") != os_.get("build"):
            ferr.append(f"{where}: os_build {f.get('os_build')!r} does not match the record "
                          f"({os_.get('build')!r}); copy it exactly, null stays null")
        if f.get("low_priv_local_access") != rec.get("low_priv_local_access"):
            ferr.append(f"{where}: low_priv_local_access {f.get('low_priv_local_access')!r} "
                          f"does not match the record ({rec.get('low_priv_local_access')!r})")

        label = cpe_label_for_os(os_)
        claimed = normalize_label(f.get("affected_product"))
        if index is None:
            affected, fixed = None, None
            if claimed is not None or f.get("fixed_build") is not None:
                ferr.append(f"{where}: there is no NVD data in this run, so affected_product "
                              f"and fixed_build must be null; do not fill them from memory")
        else:
            affected = label in index
            fixed_set = index[label]["fixed_builds"] if affected else set()
            fixed = next(iter(fixed_set)) if len(fixed_set) == 1 else None
            expected_claim = label if affected else None
            if claimed != expected_claim:
                ferr.append(f"{where}: affected_product {f.get('affected_product')!r} is wrong "
                              f"for OS {os_.get('name')} {os_.get('version')}; use the matching "
                              f"product label from lookup_vulnerability, or null if none matches")
            if f.get("fixed_build") != fixed:
                ferr.append(f"{where}: fixed_build {f.get('fixed_build')!r} does not match "
                              f"lookup_vulnerability's versionEndExcluding for this product")

        build = os_.get("build")
        expected_below = None
        if affected and fixed and build:
            expected_below = build_tuple(build) < build_tuple(fixed)
        if f.get("build_below_fixed") != expected_below:
            ferr.append(f"{where}: build_below_fixed {f.get('build_below_fixed')!r} is wrong; "
                          f"compare the builds numerically part by part (null if either is unknown)")

        # Evidence the asset cites must be cross-checked before its build is trusted.
        if affected is not False:
            missing = [e for e in rec.get("evidence_ids") or [] if e.upper() not in ledger.evidence]
            if missing:
                ferr.append(f"{where}: fetch evidence {', '.join(missing)} with "
                              f"get_evidence to cross-check this asset's facts")

        model_conflicts = []
        for c in f.get("conflicts") or []:
            ev_id = str((c or {}).get("evidence_id", "")).upper() if isinstance(c, dict) else ""
            if ev_id not in ledger.evidence:
                ferr.append(f"{where}: conflict cites evidence {ev_id or c!r} that was not "
                              f"fetched with get_evidence")
            else:
                model_conflicts.append({"evidence_id": ev_id, "ref": ledger.evidence[ev_id]["ref"],
                                        "detail": str(c.get("detail", "")), "found_by": "model"})
        code_conflicts = [{**c, "found_by": "code",
                           "detail": c["detail"].replace(
                               "the asset record", f"the asset record ({ledger.real_locator(loc)})")}
                          for c in detect_conflicts(rec, ledger.evidence)]

        findings.append({
            "locator": loc,
            "real_locator": ledger.real_locator(loc),
            "asset_ref": hit["ref"],
            "record": rec,
            "asset_id": rec.get("asset_id"),
            "instance": rec.get("instance"),
            "os_name": os_.get("name"),
            "os_version": os_.get("version"),
            "os_build": build,
            "affected": affected,
            "affected_label": label,
            "affected_reason": f"lookup_vulnerability failed: {nvd_error}" if index is None else None,
            "fixed_build": fixed,
            "fixed_build_reason": (f"lookup_vulnerability failed: {nvd_error}" if index is None
                                   else "NVD lists no single fixed build for this product"),
            "low_priv_local_access": rec.get("low_priv_local_access"),
            "exposure": rec.get("exposure"),
            "data_classification": rec.get("data_classification"),
            "data_protection": rec.get("data_protection"),
            "priority_override": rec.get("priority_override"),
            "conflicts": [c["detail"] for c in code_conflicts + model_conflicts],
            "conflict_details": code_conflicts + model_conflicts,
            "model_notes": f.get("notes"),
            "errors": ferr,
        })
        errors += ferr

    coverage = {"nvd_available": index is not None, "products": []}
    if index is not None:
        for label in sorted(index):
            how = [s["ref"] + f" search_assets('{s['query']}')" for s in ledger.searches
                   if s["complete"] and _query_covers(s["query"], label)]
            how += [a["ref"] + f" check_absence('{a['query']}') absent={a['absent']}"
                    for a in ledger.absences if a["absent"] and _query_covers(a["query"], label)]
            coverage["products"].append({"product": label, "checked_by": how})
            if not how:
                errors.append(f"affected product '{label}' was never checked in the environment: "
                              f"run search_assets with a query that covers it (complete results, "
                              f"not truncated) or check_absence")
        for loc, hit in ledger.assets.items():
            label = cpe_label_for_os(hit["record"].get("os"))
            if label in index and loc not in seen:
                r = hit["record"]
                errors.append(f"{r.get('asset_id')} {r.get('instance')} ({loc}) runs an affected "
                              f"product but is missing from findings")

    return {"findings": findings, "coverage": coverage, "nvd_available": index is not None}, errors
