"""Generate the policy-check variants from the base snapshot.

Each variant changes exactly one thing from northbridge-v1.1.json. The base file is
never modified. Run from the repo root:

    python environment/make_variants.py
"""
import copy
import json
from pathlib import Path

HERE = Path(__file__).parent
BASE = HERE / "northbridge-v1.1.json"
OUT = HERE / "variants"


def find(snapshot, asset_id, instance):
    for asset in snapshot["assets"]:
        if asset["asset_id"] == asset_id and asset["instance"] == instance:
            return asset
    raise KeyError(f"{asset_id} {instance} not found")


def set_s08_w15(s, fact):
    """Replace (or with fact=None, remove) the W15 line in evidence S08."""
    for ev in s["evidence"]:
        if ev["evidence_id"] == "S08":
            ev["facts"] = [f for f in ev["facts"] if not f.startswith("W15:")]
            if fact:
                ev["facts"].append(fact)


def variant_patched(s):
    """Applicability change: W15 receives the September 2026 update (fixed build).
    The asset record and evidence S08 are updated together, so they stay consistent."""
    w15 = find(s, "W15", "FINLEG01-FINLEG02")
    w15["os"].update({"build": "10.0.14393.9512", "last_cumulative_update": "2026-09",
                      "last_update_kb": "(September 2026 cumulative update)"})
    set_s08_w15(s, "W15: Windows Server 2016 build 10.0.14393.9512 (September 2026 update)")
    return "W15 patched to September 2026: os.build 10.0.14393.9339 -> 10.0.14393.9512 (asset record and S08)"


def variant_low_priority(s):
    """Impact change: W15 holds no PII and is reachable only from restricted zones."""
    w15 = find(s, "W15", "FINLEG01-FINLEG02")
    w15.update({"data_classification": "none", "data_protection": "n/a", "exposure": "internal_only"})
    return "W15 data_classification restricted_pii -> none; data_protection unprotected -> n/a; exposure intranet -> internal_only"


def variant_missing(s):
    """Missing evidence: W15 patch level unknown everywhere in the snapshot."""
    w15 = find(s, "W15", "FINLEG01-FINLEG02")
    w15["os"].update({"build": None, "last_cumulative_update": None, "last_update_kb": None})
    set_s08_w15(s, None)
    return "W15 os.build, last_cumulative_update, last_update_kb -> null; W15 line removed from S08"


def variant_conflict(s):
    """Conflicting evidence: patch report says September, asset record still says July."""
    set_s08_w15(s, "W15: Windows Server 2016 build 10.0.14393.9512 (September 2026 update) per patch report dated 2026-09-30")
    return "S08 fact for W15 changed to September 2026 build 9512; W15 asset record unchanged (July, build 9339)"


VARIANTS = {
    "env_patched.json": ("applicability_change", variant_patched),
    "env_low_priority.json": ("impact_change", variant_low_priority),
    "env_missing.json": ("missing_evidence", variant_missing),
    "env_conflict.json": ("conflicting_evidence", variant_conflict),
}


def main():
    base = json.loads(BASE.read_text())
    OUT.mkdir(exist_ok=True)
    for filename, (test, fn) in VARIANTS.items():
        s = copy.deepcopy(base)
        change = fn(s)
        s["snapshot_id"] = f"northbridge-v1.1-{test}"
        s["variant_of"] = base["snapshot_id"]
        s["variant_change"] = change
        (OUT / filename).write_text(json.dumps(s, indent=2))
        print(f"{filename}: {change}")


if __name__ == "__main__":
    main()
