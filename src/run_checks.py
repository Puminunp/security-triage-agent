"""Run the policy checks and controlled failures with the live model, and compare
each result with tests/expected_results.json (fixed before any run).

    python -m src.run_checks                 # all checks -> outputs/checks_<timestamp>/
    python -m src.run_checks --only 0 3b 4a  # a subset

Writes summary.md (expected vs actual table) and summary.json next to the
individual run folders.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

from src.agent import run
from src.config import REPO_ROOT

EXPECTED = REPO_ROOT / "tests" / "expected_results.json"
CONF_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def focus(assessment, asset):
    for x in assessment["assessments"]:
        if x["asset"]["asset_id"] == asset["asset_id"] and x["asset"]["instance"] == asset["instance"]:
            return x
    return None


def check_policy(exp, a, asset):
    x = focus(a, asset)
    if x is None:
        return {"actual": f"{asset['asset_id']} not assessed (run status {a['run']['status']})",
                "pass": False, "problems": ["focus asset missing"]}
    r = x["rationale"]
    actual = {"applicability": r["applicability"]["level"], "priority": r["impact"]["priority"],
              "decision": x["decision"], "rule": r["policy_rule"]}
    problems = [f"{k}: expected {exp[k]!r}, got {actual[k]!r}"
                for k in ("applicability", "priority", "decision") if exp[k] != actual[k]]
    if exp.get("must_name_sources"):
        text = json.dumps(x["rationale"]["applicability"])
        missing = [s for s in exp["must_name_sources"] if s not in text]
        if missing:
            problems.append(f"output does not name {missing}")
        actual["conflict"] = [c["detail"] for c in r["applicability"]["facts"]["conflicts"]]
    return {"actual": actual, "pass": not problems, "problems": problems}


def check_failure(exp, a, asset):
    problems = []
    actual = {"run_status": a["run"]["status"], "stop_reason": a["run"]["stop_reason"],
              "overall": a["overall"]["decision"],
              "rejected_tool_calls": a["agent_activity"]["rejected_tool_calls"],
              "lookups": [(l["tool"], l["status"]) for l in a["external_lookups"]]}
    if a["run"]["status"] != exp["run_status"]:
        problems.append(f"run_status: expected {exp['run_status']}, got {a['run']['status']}")
    if "nvd_status" in exp:
        st = [l["status"] for l in a["external_lookups"] if l["tool"] == "lookup_vulnerability"]
        if exp["nvd_status"] not in st:
            problems.append(f"NVD status: expected {exp['nvd_status']}, got {st}")
    if "overall" in exp and a["overall"]["decision"] != exp["overall"]:
        problems.append(f"overall: expected {exp['overall']}, got {a['overall']['decision']}")
    if "stop_reason_contains" in exp and exp["stop_reason_contains"] not in (a["run"]["stop_reason"] or ""):
        problems.append(f"stop reason does not name {exp['stop_reason_contains']}")
    if "min_rejected" in exp and a["agent_activity"]["rejected_tool_calls"] < exp["min_rejected"]:
        problems.append("no tool call was rejected")
    if "decision" in exp:
        x = focus(a, asset)
        actual["decision"] = x["decision"] if x else None
        if not x or x["decision"] != exp["decision"]:
            problems.append(f"decision: expected {exp['decision']}, got {actual['decision']}")
        if x and exp.get("confidence_at_most"):
            actual["confidence"] = x["confidence"]["level"]
            if CONF_ORDER.get(x["confidence"]["level"], 9) > CONF_ORDER[exp["confidence_at_most"]]:
                problems.append(f"confidence above {exp['confidence_at_most']}")
    return {"actual": actual, "pass": not problems, "problems": problems}


def check_scan(exp, a):
    problems = []
    got = {f"{x['asset']['asset_id']} {x['asset']['instance']}": x["decision"] for x in a["assessments"]}
    for k, v in exp["non_low"].items():
        if got.get(k) != v:
            problems.append(f"{k}: expected {v}, got {got.get(k)}")
    extra = {k: v for k, v in got.items() if k not in exp["non_low"] and v != "Low"}
    if extra:
        problems.append(f"unexpected non-Low: {extra}")
    return {"actual": {k: v for k, v in got.items() if v != "Low"} | {"Low": sum(v == "Low" for v in got.values())},
            "pass": not problems, "problems": problems}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--only", nargs="*", help="check IDs to run (default: all)")
    args = p.parse_args(argv)
    exp = json.loads(EXPECTED.read_text(encoding="utf-8"))
    asset = exp["focus_asset"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_root = f"outputs/checks_{stamp}"
    rows = []
    checks = [("policy", c) for c in exp["policy_checks"]] + [("failure", c) for c in exp["failure_checks"]]
    for kind, c in checks:
        if args.only and c["id"] not in args.only:
            continue
        print(f"[{c['id']}] {c['name']} ...", flush=True)
        a, run_dir = run(exp["cve_id"], snapshot_path=c["snapshot"], faults=c["faults"],
                         label=f"check{c['id']}", out_root=out_root)
        res = (check_policy if kind == "policy" else check_failure)(c, a, asset)
        if c["id"] == "0":
            scan = check_scan(exp["secondary_scan"], a)
            rows.append({"id": "0s", "name": "Secondary scan (all assets, base snapshot)", "kind": "scan",
                         "expected": exp["secondary_scan"], **scan,
                         "run_dir": str(run_dir.relative_to(REPO_ROOT))})
        rows.append({"id": c["id"], "name": c["name"], "kind": kind, "expected": c, **res,
                     "run_dir": str(run_dir.relative_to(REPO_ROOT))})
        print(f"     {'PASS' if res['pass'] else 'FAIL'} {res['problems'] or ''}", flush=True)

    rows.sort(key=lambda r: r["id"])
    (REPO_ROOT / out_root).mkdir(parents=True, exist_ok=True)
    (REPO_ROOT / out_root / "summary.json").write_text(json.dumps(rows, indent=2, default=str),
                                                         encoding="utf-8")
    md = [f"# Check results ({stamp})", "", "| # | Check | Expected | Actual | Pass | Run |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        e = r["expected"]
        if r["kind"] == "policy":
            exp_s = f"{e['applicability']} / {e['priority']} / **{e['decision']}**"
            act = r["actual"]
            act_s = (f"{act['applicability']} / {act['priority']} / **{act['decision']}** ({act['rule']})"
                     if isinstance(act, dict) else act)
        elif r["kind"] == "scan":
            exp_s = ", ".join(f"{k}: {v}" for k, v in e["non_low"].items()) + "; rest Low"
            act_s = ", ".join(f"{k}: {v}" for k, v in r["actual"].items())
        else:
            exp_s = ", ".join(f"{k}={v}" for k, v in e.items()
                              if k not in ("id", "name", "snapshot", "faults", "note"))
            act_s = ", ".join(f"{k}={v}" for k, v in r["actual"].items() if v not in (None, []))
        md.append(f"| {r['id']} | {r['name']} | {exp_s} | {act_s} | {'PASS' if r['pass'] else 'FAIL: ' + '; '.join(r['problems'])} | `{r['run_dir']}` |")
    (REPO_ROOT / out_root / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\nsummary: {out_root}/summary.md")
    return 0 if all(r["pass"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
