"""Command line entry point.

    python -m src.main                                   # main run, CVE-2026-85880, base snapshot
    python -m src.main --snapshot environment/variants/env_patched.json --label check1
    python -m src.main --fault nvd-down --label fail_nvd
"""
import argparse
import sys

from src.agent import run
from src.faults import FAULTS


def main(argv=None):
    p = argparse.ArgumentParser(description="Security triage agent: rate one CVE against Northbridge.")
    p.add_argument("--cve", default="CVE-2026-85880")
    p.add_argument("--snapshot", help="environment snapshot (default: config/settings.yaml)")
    p.add_argument("--fault", action="append", choices=FAULTS, default=[],
                   help="inject a controlled failure (repeatable)")
    p.add_argument("--label", help="suffix for the run folder name")
    p.add_argument("--out", default="outputs", help="output folder (default: outputs)")
    a = p.parse_args(argv)

    assessment, run_dir = run(a.cve, snapshot_path=a.snapshot, faults=a.fault, label=a.label,
                              out_root=a.out)
    o, r = assessment["overall"], assessment["run"]
    print(f"run {r['run_id']}: {r['status']}" + (f" ({r['stop_reason']})" if r["stop_reason"] else ""))
    print(f"overall: {o['decision'] or 'NO RATING'}  {o['counts']}")
    for x in assessment["assessments"]:
        if x["decision"] != "Low":
            print(f"  {x['asset']['asset_id']:<4} {x['asset']['instance']:<40} {x['decision']:<22} "
                  f"{x['rationale']['policy_rule']}")
    print(f"saved: {run_dir}")
    return 0 if r["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
