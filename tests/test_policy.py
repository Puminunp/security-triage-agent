"""src/policy.py must match reference/policy_reference.py (Student A's executable
spec of docs/rating_policy.md) on the base snapshot and every variant."""
import importlib.util

import pytest

from conftest import BASE, VARIANTS, nvd_data, read_json
from src import policy
from src.config import REPO_ROOT
from src.validation import cpe_label_for_os, detect_conflicts, nvd_index

spec = importlib.util.spec_from_file_location("policy_reference",
                                              REPO_ROOT / "reference" / "policy_reference.py")
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)

THREAT = {"cvss_score": 7.8, "in_kev": True}


def facts_from_snapshot(snapshot, asset, index):
    label = cpe_label_for_os(asset["os"])
    affected = label in index
    fixed = next(iter(index[label]["fixed_builds"])) if affected and index[label]["fixed_builds"] else None
    evidence = {e["evidence_id"]: {"record": e, "ref": "-"} for e in snapshot["evidence"]}
    return {**asset, "os_build": asset["os"].get("build"), "affected": affected,
            "fixed_build": fixed,
            "conflicts": [c["detail"] for c in detect_conflicts(asset, evidence)]}


@pytest.mark.parametrize("path", [BASE, *VARIANTS.values()])
def test_matches_reference_on_every_asset(path):
    snapshot = read_json(REPO_ROOT / path)
    index = nvd_index(nvd_data())
    for asset in snapshot["assets"]:
        ref = reference.rate(snapshot, asset)
        got = policy.rate(facts_from_snapshot(snapshot, asset, index), THREAT)
        label = f"{path} {asset['asset_id']} {asset['instance']}"
        assert got["applicability"] == ref["applicability"], label
        assert got["priority"] == ref["priority"], label
        assert got["decision"] == ref["decision"], label


def asset(**kw):
    base = {"affected": True, "fixed_build": "10.0.14393.9512", "os_build": "10.0.14393.9339",
            "low_priv_local_access": True, "exposure": "intranet",
            "data_classification": "restricted_pii", "data_protection": "unprotected",
            "priority_override": None, "conflicts": []}
    return {**base, **kw}


def test_severity_bands():
    assert [policy.severity_band(s) for s in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, None)] == \
        ["Critical", "High", "High", "Medium", "Medium", "Low", "Low", None]


def test_builds_compare_numerically_not_as_text():
    # As text "10.0.14393.10000" < "10.0.14393.9512"; numerically it is higher.
    r = policy.rate(asset(os_build="10.0.14393.10000"), THREAT)
    assert r["applicability"] == "Not applicable"


def test_kev_raises_and_caps():
    no_kev = policy.rate(asset(data_classification="none", exposure="internal_only"),
                         {"cvss_score": 7.8, "in_kev": False})
    kev = policy.rate(asset(data_classification="none", exposure="internal_only"), THREAT)
    assert (no_kev["decision"], kev["decision"]) == ("Low", "Medium")
    assert policy.rate(asset(), THREAT)["decision"] == "High"  # capped


def test_partial_lowers_after_kev():
    r = policy.rate(asset(low_priv_local_access=False), THREAT)
    assert r["applicability"] == "Partial"
    assert r["rule"] == "P1 x High = High; KEV +1 -> High; Partial -1 -> Medium"


def test_unknowns_never_produce_a_rating():
    for kw in ({"os_build": None}, {"low_priv_local_access": None}, {"affected": None},
               {"fixed_build": None}, {"conflicts": ["S08 disagrees"]}):
        assert policy.rate(asset(**kw), THREAT)["decision"] == policy.INSUFFICIENT, kw
    assert policy.rate(asset(), {"cvss_score": None, "in_kev": True})["decision"] == policy.INSUFFICIENT
    assert policy.rate(asset(exposure=None), THREAT)["decision"] == policy.INSUFFICIENT


def test_not_applicable_is_low_even_for_critical():
    r = policy.rate(asset(os_build="10.0.14393.9512"), {"cvss_score": 9.8, "in_kev": True})
    assert r["decision"] == "Low"


def test_kev_unknown_applies_no_modifier_and_lowers_confidence():
    r = policy.rate(asset(data_classification="none", exposure="internal_only"),
                    {"cvss_score": 7.8, "in_kev": None})
    assert r["decision"] == "Low" and "KEV status unknown" in r["rule"]
    level, _ = policy.confidence(r, ["T1"], set(), kev_unknown=True)
    assert level == "Low"


def test_confidence_levels():
    r = policy.rate(asset(), THREAT)
    assert policy.confidence(r, ["T1", "T2"], set())[0] == "High"
    assert policy.confidence(r, ["T1", "S08"], set())[0] == "Medium"
    assert policy.confidence(r, ["T1"], {"lookup_vulnerability"})[0] == "Medium"
    ins = policy.rate(asset(os_build=None), THREAT)
    assert policy.confidence(ins, ["T1"], set())[0] is None
