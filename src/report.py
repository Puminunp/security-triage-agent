"""Build and save the structured assessment (assessment.json) and a readable report.md.

Every fact in the assessment is taken from the evidence ledger (tool results)
or the policy result; the model contributes only its notes and the
action text, both labeled.
"""
import json
import re
from pathlib import Path

from src.config import REPO_ROOT
from src.policy import INSUFFICIENT

ORDER = {"High": 0, "Medium": 1, INSUFFICIENT: 2, "Low": 3}
CHANGES = REPO_ROOT / "environment" / "CHANGES.md"
DECISIVE_NULLS = ("os.build", "low_priv_local_access")


def _assumptions_by_asset():
    """Assumptions A1-A15 from environment/CHANGES.md, keyed by the asset IDs they affect."""
    out = {}
    try:
        text = CHANGES.read_text(encoding="utf-8")
    except OSError:
        return out
    for m in re.finditer(r"^\| (A\d+) \| (.+?) \| (.+?) \|$", text, re.M):
        for asset_id in re.findall(r"\b[A-Z]\d{2}\b", m.group(3)):
            out.setdefault(asset_id, []).append(f"{m.group(1)} (S07): {m.group(2)}")
    return out


def _threat_section(info, threat, ledger):
    nvd, cvss = threat["nvd"] or {}, threat["cvss"] or {}
    entry = (threat["kev"] or {}).get("entry") or {}
    sources = []
    if ledger.nvd:
        sources.append(ledger.citation(ledger.nvd["ref"], fact="description, CVSS v3.1, affected products, fixed builds"))
    if ledger.kev:
        sources.append(ledger.citation(ledger.kev["ref"], fact="KEV listing, dateAdded, dueDate, requiredAction"))
    return {
        "cve_id": info["cve_id"],
        "description": nvd.get("description"),
        "published": nvd.get("published"),
        "cwe": nvd.get("cwe"),
        "cvss_v31": {"base_score": cvss.get("base_score"), "vector": cvss.get("vector"),
                     "score_source": cvss.get("source"), "score_type": cvss.get("score_used")},
        "kev": {"in_kev": threat["in_kev"], "source": threat["kev_source"],
                "date_added": entry.get("dateAdded"), "due_date": entry.get("dueDate"),
                "required_action": entry.get("requiredAction"),
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                "note": "absence from KEV does not establish safety"},
        "severity_note": "CVSS is the flaw's technical severity in general; the decision per "
                         "asset is local risk from the applicability-and-impact policy.",
        "sources": sources,
    }


def _assessment_item(item, ledger, assumptions):
    f, res, rec = item["finding"], item["result"], item["finding"]["record"]
    evidence = [ledger.citation(f["asset_ref"], locator=f["real_locator"],
                                fact=f"asset record: OS {f['os_name']} build {f['os_build']}, "
                                     f"low_priv_local_access={f['low_priv_local_access']}, "
                                     f"data={f['data_classification']}/{f['data_protection']}, "
                                     f"exposure={f['exposure']}")]
    for ev_id in rec.get("evidence_ids") or []:
        hit = ledger.evidence.get(ev_id.upper())
        if hit:
            r = hit["record"]
            evidence.append({**ledger.citation(hit["ref"]), "evidence_id": ev_id,
                             "fact": f"{r.get('title')} ({r.get('origin', 'scenario')}, {r.get('date')})"})
    if ledger.nvd:
        evidence.append(ledger.citation(ledger.nvd["ref"],
                                        fact=f"affected product {f['affected_label']}: "
                                             f"{'listed' if f['affected'] else 'not listed'}; "
                                             f"fixed build {f['fixed_build']}"))
    if ledger.kev and res["applicability"] in ("Confirmed", "Partial"):
        evidence.append(ledger.citation(ledger.kev["ref"], fact="CVE listed in CISA KEV"))

    unknown_paths = [p for p in _null_paths(rec)]
    decisive = [p for p in unknown_paths if p in DECISIVE_NULLS]
    status = "needs_analyst_review" if res["decision"] == INSUFFICIENT else "rated"
    return {
        "asset": {"asset_id": f["asset_id"], "instance": f["instance"], "count": rec.get("count"),
                  "role": rec.get("role"), "zone": rec.get("zone"), "locator": f["real_locator"],
                  "source_mode": rec.get("source_mode")},
        "decision": res["decision"],
        "status": status,
        "rationale": {
            "applicability": {"level": res["applicability"], "reason": res["applicability_reason"],
                              "facts": {"os": f"{f['os_name']} {f['os_version']}",
                                        "os_build": f["os_build"],
                                        "affected_product": f["affected_label"] if f["affected"] else None,
                                        "fixed_build": f["fixed_build"],
                                        "low_priv_local_access": f["low_priv_local_access"],
                                        "conflicts": f["conflict_details"]}},
            "impact": {"priority": res["priority"], "reason": res["priority_reason"],
                       "data_classification": f["data_classification"],
                       "data_protection": f["data_protection"], "exposure": f["exposure"],
                       "priority_override": f["priority_override"],
                       "business_service": rec.get("business_service")},
            "severity": {"band": res["severity_band"]},
            "modifiers": {"kev": res["kev_modifier"], "partial": res["partial_modifier"]},
            "policy_rule": res["rule"],
            "policy": "docs/rating_policy.md v1.0 (applied by src/policy.py, not by the model)",
        },
        "evidence": evidence,
        "assumptions": assumptions.get(f["asset_id"], []),
        "unknowns": {"decisive": decisive,
                     "non_decisive": [p for p in unknown_paths if p not in DECISIVE_NULLS]},
        "confidence": {**item["confidence"], "decisive_sources": item["decisive_sources"]},
        "action": item.get("action"),
        "model_notes": f["model_notes"],
        "validation_errors": f["errors"],
    }


def _null_paths(value, prefix=""):
    if value is None:
        return [prefix]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _null_paths(v, f"{prefix}.{k}" if prefix else k)]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _null_paths(v, f"{prefix}[{i}]")]
    return []


def build_assessment(run_id, started, finished, info, config, outcome, ledger, threat, rated):
    assumptions = _assumptions_by_asset()
    items = sorted((_assessment_item(i, ledger, assumptions) for i in rated),
                   key=lambda a: (ORDER[a["decision"]], a["asset"]["asset_id"], a["asset"]["instance"]))
    counts = {}
    for a in items:
        counts[a["decision"]] = counts.get(a["decision"], 0) + 1

    finding_errors = {e for i in rated for e in i["finding"]["errors"]}
    unresolved = [e for e in outcome["errors"] if e not in finding_errors]
    if outcome["status"] == "completed" and unresolved:
        # Coverage gaps or unverifiable findings remain: never report "Low" by omission.
        decisions = [a["decision"] for a in items] + [INSUFFICIENT]
        overall = min(decisions, key=ORDER.get)
        overall_note = ("Submission still failed validation after the last attempt, so the "
                        "asset list may be incomplete: " + "; ".join(unresolved))
    elif outcome["status"] == "completed":
        overall = min((a["decision"] for a in items), key=ORDER.get, default="Low")
        overall_note = (f"Highest per-asset decision across {len(items)} assessed asset records."
                        if items else "No asset record runs an affected product.")
    elif outcome["status"] == "stopped_decisive_lookup_failed":
        overall = INSUFFICIENT
        overall_note = outcome["stop_reason"]
    else:
        overall = None
        overall_note = f"No rating produced: {outcome['stop_reason']}"

    lookups = [{"ref": e["ref"], "tool": e["tool"], "args": e["args"], "status": e["result"].get("status"),
                "source_mode": e["result"].get("source_mode"), "error": e["result"].get("error")}
               for e in ledger.entries if e["tool"] in ("lookup_vulnerability", "lookup_kev")]
    return {
        "schema_version": "1.0",
        "run": {"run_id": run_id, "label": config["label"], "started_at": started,
                "finished_at": finished, "status": outcome["status"],
                "stop_reason": outcome["stop_reason"], "faults": config["faults"],
                "model": config["model"].get("model"), "prompt_version": config["prompt_version"],
                "code_version": config["code_version"]},
        "intake": info,
        "threat": _threat_section(info, threat, ledger),
        "overall": {"decision": overall, "note": overall_note, "counts": counts,
                    "unresolved_validation_errors": unresolved,
                    "needs_analyst_review": [f"{a['asset']['asset_id']} {a['asset']['instance']}"
                                             for a in items if a["status"] == "needs_analyst_review"]},
        "assessments": items,
        "coverage": (outcome["validated"] or {}).get("coverage"),
        "external_lookups": lookups,
        "agent_activity": {"tool_calls": len(ledger.entries), "rejected_tool_calls": ledger.rejected,
                           "submissions": outcome["submissions"],
                           "final_validation_errors": outcome["errors"],
                           "model_summary": (outcome["submission"] or {}).get("summary")
                           if isinstance(outcome["submission"], dict) else None},
        "human_review": {"status": "pending", "reviewer": None, "date": None,
                         "checklist": "docs/evidence_review.md"},
    }


def _one_line(text):
    return " ".join(str(text or "").split())


def render_markdown(a):
    t, o, run = a["threat"], a["overall"], a["run"]
    lines = [f"# Triage report: {a['intake']['cve_id']}", "",
             f"- **Run:** `{run['run_id']}` · status **{run['status']}** · model `{run['model']}` "
             f"· faults: {', '.join(run['faults']) or 'none'}",
             f"- **Snapshot:** `{a['intake']['snapshot_path']}` ({a['intake']['snapshot_id']}, "
             f"{a['intake']['snapshot_source_mode']})",
             f"- **Risk question:** {a['intake']['risk_question']}", "",
             f"## Overall: {o['decision'] or 'NO RATING'}", "", o["note"], ""]
    if run["stop_reason"]:
        lines += [f"> Stopped: {run['stop_reason']}", ""]
    if o["counts"]:
        lines += ["Counts: " + ", ".join(f"{k} {v}" for k, v in o["counts"].items()), ""]
    lines += ["## Threat", "",
              f"- {t['description']}",
              f"- CVSS v3.1 {t['cvss_v31']['base_score']} `{t['cvss_v31']['vector']}` "
              f"({t['cvss_v31']['score_type']}, {t['cvss_v31']['score_source']})",
              f"- KEV: {t['kev']['in_kev']} (source: {t['kev']['source']}; added {t['kev']['date_added']}, "
              f"due {t['kev']['due_date']})",
              f"- {t['severity_note']}", ""]
    lines += ["## External lookups", "", "| Ref | Tool | Status | Mode | Error |", "|---|---|---|---|---|"]
    for l in a["external_lookups"]:
        lines.append(f"| {l['ref']} | {l['tool']} | {l['status']} | {l['source_mode']} | {l['error'] or ''} |")
    lines += ["", "## Per-asset decisions", "",
              "| Asset | Decision | Applicability | Priority | Rule | Confidence |",
              "|---|---|---|---|---|---|"]
    for x in a["assessments"]:
        r = x["rationale"]
        lines.append(f"| {x['asset']['asset_id']} {x['asset']['instance']} | **{x['decision']}** | "
                     f"{r['applicability']['level']} | {r['impact']['priority']} | {r['policy_rule']} | "
                     f"{x['confidence']['level'] or 'n/a'} |")
    for x in a["assessments"]:
        if x["decision"] == "Low":
            continue
        r = x["rationale"]
        lines += ["", f"### {x['asset']['asset_id']} {x['asset']['instance']}: {x['decision']}", "",
                  f"- **Role / zone:** {x['asset']['role']} / {x['asset']['zone']}",
                  f"- **Applicability:** {r['applicability']['level']}. {r['applicability']['reason']}",
                  f"- **Impact:** {r['impact']['priority']} ({r['impact']['reason']})",
                  f"- **Rule:** {r['policy_rule']}",
                  f"- **Confidence:** {x['confidence']['level']} ({x['confidence']['reason']})",
                  f"- **Recommended action** ({x['action']['drafted_by']}): {_one_line(x['action']['recommended_action'])}",
                  f"- **Would change the decision:** {_one_line(x['action']['would_change_decision'])}",
                  f"- **Decisive unknowns:** {', '.join(x['unknowns']['decisive']) or 'none'}",
                  "- **Assumptions:** " + ("; ".join(x["assumptions"]) or "none"),
                  "- **Evidence:**"]
        for e in x["evidence"]:
            lines.append(f"  - {e['ref']} `{e['tool']}` {e.get('evidence_id') or e.get('source_id') or ''} "
                         f"{e['source']} [{e['source_mode']}, {e['status']}, {e['retrieved_at']}]: {e['fact']}")
    lines += ["", "## Human review", "", "Pending. Use `docs/evidence_review.md`.", ""]
    return "\n".join(lines)


def save(run_dir, assessment, config, trace, messages, ledger):
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    def dump(name, obj):
        with open(run_dir / name, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2, default=str)

    dump("assessment.json", assessment)
    dump("config.json", config)
    dump("messages.json", messages)
    dump("tool_results.json", [{"ref": e["ref"], "tool": e["tool"], "args": e["args"],
                                "result": e["result"]} for e in ledger.entries])
    with open(run_dir / "trace.jsonl", "w", encoding="utf-8") as fh:
        for ev in trace.events:
            fh.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")
    (run_dir / "report.md").write_text(render_markdown(assessment), encoding="utf-8")
