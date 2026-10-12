"""Orchestration: intake -> model-driven evidence gathering -> validation -> policy
-> action drafting -> saved assessment.

    from src.agent import run
    assessment, run_dir = run("CVE-2026-85880")

Who does what:
  model  chooses tools and builds their queries, reads results, extracts facts,
         drafts the recommended-action text
  code   runs and validates every tool call, checks every extracted fact against
         the tool results, applies the rating policy, enforces stop rules, saves
  human  reviews the saved assessment and its citations (docs/evidence_review.md)
"""
import hashlib
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from src import faults as fault_mod
from src import policy, prompts, report
from src.config import REPO_ROOT, load_settings, resolve
from src.evidence import Ledger
from src.llm import LLMError, OllamaClient
from src.tools import registry
from src.validation import validate

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"


class Trace:
    """Ordered record of everything that happened in a run (saved as trace.jsonl)."""

    def __init__(self):
        self.events = []
        self.t0 = time.monotonic()

    def add(self, kind, **data):
        self.events.append({"seq": len(self.events) + 1,
                            "t": round(time.monotonic() - self.t0, 3), "event": kind, **data})


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_version():
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                                text=True, timeout=5).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "src", "config", "environment"],
                               cwd=REPO_ROOT, capture_output=True, text=True,
                               timeout=5).stdout.strip()
        return {"commit": commit or None, "uncommitted_changes": bool(dirty)}
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "uncommitted_changes": None}


# --- step 1: intake ---------------------------------------------------------

def intake(cve_id, snapshot_path, settings):
    if not isinstance(cve_id, str) or not re.fullmatch(CVE_PATTERN, cve_id):
        raise ValueError(f"not a CVE ID: {cve_id!r}")
    path = resolve(snapshot_path or settings["environment_snapshot"])
    raw = path.read_bytes()
    snap = json.loads(raw)
    return {
        "cve_id": cve_id,
        "risk_question": (f"What is the risk that {cve_id} is exploited on Northbridge Services "
                          f"assets, given environment snapshot {snap.get('snapshot_id')} "
                          f"(as of {snap.get('snapshot_date')})?"),
        "snapshot_path": str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path),
        "snapshot_file": path.name,
        "snapshot_id": snap.get("snapshot_id"),
        "snapshot_date": snap.get("snapshot_date"),
        "snapshot_source_mode": snap.get("source_mode"),
        "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
        "variant_change": snap.get("variant_change"),
    }


# --- step 2: model-driven evidence gathering -------------------------------

def model_view(entry):
    """The compact, blinded copy of a tool result that goes back to the model.

    Drops fields the model does not need to extract facts (echoed args,
    timestamps, NVD reference URLs, per-search duplicate unknown_fields) to keep
    the context short; long contexts made Ollama Cloud fail more often. The
    ledger and tool_results.json keep the full result.
    """
    b = entry["blinded"]
    view = {"ref": entry["ref"], "status": b.get("status"), "source": b.get("source"),
            "source_mode": b.get("source_mode"), "error": b.get("error")}
    data = b.get("data")
    if isinstance(data, dict):
        data = {k: v for k, v in data.items() if k not in ("references", "snapshot_id")}
        if "matches" in data:
            data["matches"] = [{"locator": m["locator"], "asset": m["asset"]} for m in data["matches"]]
    view["data"] = data
    if b.get("unknown_fields") and not (isinstance(data, dict) and "matches" in data):
        view["unknown_fields"] = b["unknown_fields"]
    elif isinstance(data, dict) and "matches" in data:
        view["note_on_nulls"] = "null values in asset records are unknown; keep them null"
    return {k: v for k, v in view.items() if v is not None}


def investigate(llm, intake_info, snapshot_path, ledger, trace, cfg, faults):
    """Run the tool loop until the model's findings are accepted or a stop rule fires.

    Returns {"status", "stop_reason", "validated", "submission", "errors",
             "submissions", "messages"}.
    """
    user = prompts.USER_TEMPLATE.format(cve_id=intake_info["cve_id"])
    bad_tool_pending = "bad-tool" in faults
    messages = [{"role": "system", "content": prompts.SYSTEM_PROMPT},
                {"role": "user", "content": user}]
    tools = registry.TOOL_SCHEMAS + [prompts.SUBMIT_SCHEMA]
    out = {"status": None, "stop_reason": None, "validated": None, "submission": None,
           "errors": [], "submissions": 0, "messages": messages}
    tool_calls = text_replies = 0

    def stop(status, reason):
        trace.add("stop", status=status, reason=reason)
        out.update(status=status, stop_reason=reason)
        return out

    for turn in range(1, cfg["max_model_turns"] + 1):
        try:
            msg = llm.chat(messages, tools)
        except LLMError as exc:
            return stop("stopped_model_error", f"model unavailable: {exc}")
        calls = msg.get("tool_calls") or []
        if bad_tool_pending and calls:
            # Controlled failure 4c: the model's first tool request becomes a request for a
            # tool that does not exist. The model sees the rejection and must recover.
            trace.add("fault_injected", fault="bad-tool", replaced_call=calls[0],
                      with_call=fault_mod.BAD_TOOL_CALL)
            calls = [fault_mod.BAD_TOOL_CALL] + calls[1:]
            msg = {**msg, "tool_calls": calls}
            bad_tool_pending = False
        trace.add("model_response", turn=turn, content=msg.get("content"),
                  thinking=msg.get("thinking"),
                  tool_calls=[{"name": c.get("function", {}).get("name"),
                               "arguments": c.get("function", {}).get("arguments")} for c in calls])
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         "tool_calls": calls})

        if not calls:
            text_replies += 1
            if text_replies > cfg["max_text_replies"]:
                return stop("stopped_no_submission",
                            f"model replied {text_replies} times without calling a tool")
            messages.append({"role": "user", "content": "Do not answer in text. Continue with "
                             "tool calls, and finish by calling submit_findings."})
            continue

        for call in calls:
            fn = call.get("function", {})
            name, args = fn.get("name"), fn.get("arguments")
            tool_calls += 1
            if tool_calls > cfg["max_tool_calls"]:
                return stop("stopped_tool_budget", f"more than {cfg['max_tool_calls']} tool calls")

            if name == "submit_findings":
                out["submissions"] += 1
                validated, errors = validate(args, ledger)
                trace.add("validation", attempt=out["submissions"], passed=not errors,
                          errors=errors, findings=len((args or {}).get("findings", []) or [])
                          if isinstance(args, dict) else None)
                if not errors or out["submissions"] >= cfg["max_submissions"]:
                    out.update(validated=validated, submission=args, errors=errors)
                    if validated is None:
                        return stop("stopped_validation_failed",
                                    "submission was malformed after the last attempt")
                    trace.add("findings_accepted", with_errors=bool(errors))
                    out["status"] = "completed"
                    return out
                reply = {"status": "rejected", "attempt": out["submissions"],
                         "attempts_left": cfg["max_submissions"] - out["submissions"],
                         "errors": errors}
            else:
                result = registry.execute(name, args, snapshot_path=snapshot_path)
                entry = ledger.add(name, args, result)
                trace.add("tool_call", ref=entry["ref"], tool=name, args=args,
                          status=result.get("status"), source_mode=result.get("source_mode"),
                          source=entry["blinded"].get("source"), error=result.get("error"),
                          rejected=entry["rejected"])
                reply = model_view(entry)
                if ledger.rejected >= cfg["max_rejected_calls"]:
                    return stop("stopped_rejected_calls",
                                f"{ledger.rejected} tool calls rejected (unknown tool or invalid "
                                f"arguments); no rating produced")
                if (name == "lookup_vulnerability" and not entry["rejected"]
                        and result.get("status") in ("error", "not_found")):
                    return stop("stopped_decisive_lookup_failed",
                                f"lookup_vulnerability failed ({result.get('error') or result.get('status')}); "
                                f"affected products and fixed builds are unknown")
            messages.append({"role": "tool", "tool_name": name,
                             "content": json.dumps(reply, ensure_ascii=False)})

    return stop("stopped_turn_limit", f"no accepted submission after {cfg['max_model_turns']} model turns")


# --- step 3: policy ---------------------------------------------------------

def threat_facts(ledger):
    nvd = ledger.nvd["result"]["data"] if ledger.nvd else {}
    cvss = (nvd or {}).get("cvss_v31") or {}
    kev_entry = ledger.kev["result"]["data"] if ledger.kev else None
    if kev_entry is not None:
        in_kev, kev_source = kev_entry.get("in_kev"), "T2 lookup_kev"
    elif nvd and nvd.get("kev"):
        in_kev, kev_source = nvd["kev"].get("in_kev"), "T1 NVD KEV fields (lookup_kev failed)"
    else:
        in_kev, kev_source = None, "unknown (lookup_kev failed and no NVD KEV fields)"
    return {"cvss_score": cvss.get("base_score"), "cvss": cvss, "in_kev": in_kev,
            "kev_source": kev_source, "nvd": nvd, "kev": kev_entry}


def decisive_sources(finding, result):
    appl = result["applicability"]
    if appl == "Not applicable" and finding["affected"] is False:
        return ["T1"]
    sources = ["T1", "S08"]
    if appl in ("Confirmed", "Partial"):
        sources.append("T2")
        if "S07" in (finding["record"].get("evidence_ids") or []):
            sources.append("S07")
    return sources


def apply_policy(validated, ledger, threat, submissions):
    rated = []
    for f in validated["findings"]:
        if f["errors"]:
            res = {"applicability": "Unknown",
                   "applicability_reason": "the model's extracted facts failed validation after "
                                           f"{submissions} attempt(s): " + "; ".join(f["errors"]),
                   "priority": policy.priority(f)[0], "priority_reason": policy.priority(f)[1],
                   "severity_band": policy.severity_band(threat["cvss_score"]),
                   "kev_modifier": None, "partial_modifier": None,
                   "decision": policy.INSUFFICIENT,
                   "rule": "facts not verified against tool evidence -> INSUFFICIENT_EVIDENCE"}
        else:
            res = policy.rate(f, threat)
        srcs = decisive_sources(f, res)
        cached = {t for t in ledger.cached_sources()
                  if t == "lookup_vulnerability" or res["applicability"] in ("Confirmed", "Partial")}
        kev_unknown = threat["in_kev"] is None and res["applicability"] in ("Confirmed", "Partial")
        level, why = policy.confidence(res, srcs, cached, kev_unknown)
        rated.append({"finding": f, "result": res, "decisive_sources": srcs,
                      "confidence": {"level": level, "reason": why}})
    return rated


# --- step 4: action drafting -----------------------------------------------

def template_action(item, threat):
    res, f = item["result"], item["finding"]
    if res["decision"] == "Low" and res["applicability"] == "Not applicable":
        if f["affected"] is False:
            return ("No action for this CVE: the product is not affected.",
                    "Evidence that the asset runs a different, affected OS version.")
        return (f"No action for this CVE: build {f['os_build']} is at or above the fixed build "
                f"{f['fixed_build']}. Keep the normal monthly patch cadence.",
                "A patch report showing a build below the fixed build.")
    if res["decision"] == policy.INSUFFICIENT:
        return ("Analyst review: obtain the missing or conflicting decisive fact "
                f"({res['applicability_reason']}) from a current patch or inventory report.",
                "A verified, current OS build (and access path) for this asset.")
    return (f"Install the cumulative update that brings the build to {f['fixed_build']} or later.",
            "A patch report showing the fixed build, or proof that no low-privilege account can "
            "log on locally.")


def _as_text(value):
    """The model sometimes returns a list of steps; store one numbered string."""
    if isinstance(value, list):
        return " ".join(f"{i}) {str(v).strip()}" for i, v in enumerate(value, 1))
    return str(value).strip()


def draft_actions(llm, rated, threat, intake_info, trace, ledger):
    """Model drafts action text for non-Low results; Low results use a fixed template."""
    keys, lines = {}, []
    for i, item in enumerate(rated, 1):
        if item["result"]["decision"] == "Low":
            continue
        f, res, rec = item["finding"], item["result"], item["finding"]["record"]
        key = f"A{i}"
        keys[key] = item
        lines.append(json.dumps(ledger.blind({
            "key": key, "asset": f"{f['asset_id']} {f['instance']}", "role": rec.get("role"),
            "zone": rec.get("zone"), "os": f"{f['os_name']} build {f['os_build']}",
            "fixed_build": f["fixed_build"], "decision": res["decision"], "rule": res["rule"],
            "applicability": f"{res['applicability']}: {res['applicability_reason']}",
            "priority": f"{res['priority']} ({res['priority_reason']})",
            "config": rec.get("config"), "notes": rec.get("notes"),
            "business_service": rec.get("business_service"),
        }), ensure_ascii=False))

    drafted = {}
    if keys:
        kev = threat["kev"] or {}
        entry = kev.get("entry") or {}
        prompt = prompts.ACTION_TEMPLATE.format(
            cve_id=intake_info["cve_id"],
            threat=(threat["nvd"] or {}).get("description"),
            kev=json.dumps({"in_kev": threat["in_kev"], "dateAdded": entry.get("dateAdded"),
                            "dueDate": entry.get("dueDate"),
                            "requiredAction": entry.get("requiredAction")}),
            snapshot_date=intake_info.get("snapshot_date"),
            assets="\n".join(lines))
        try:
            msg = llm.chat([{"role": "system", "content": prompts.ACTION_SYSTEM},
                            {"role": "user", "content": prompt}], json_mode=True)
            parsed = json.loads(msg.get("content") or "{}")
            for key in keys:
                v = parsed.get(key)
                if isinstance(v, dict) and v.get("recommended_action"):
                    drafted[key] = v
            trace.add("action_drafting", drafted=sorted(drafted), missing=sorted(set(keys) - set(drafted)))
        except (LLMError, ValueError, AttributeError) as exc:
            trace.add("action_drafting", error=f"{type(exc).__name__}: {exc}",
                      fallback="template text used")

    for i, item in enumerate(rated, 1):
        d = drafted.get(f"A{i}")
        if d:
            item["action"] = {"recommended_action": _as_text(d["recommended_action"]),
                              "would_change_decision": _as_text(d.get("would_change_decision", "")),
                              "drafted_by": "model (rating fixed by policy code)"}
        else:
            act, change = template_action(item, threat)
            item["action"] = {"recommended_action": act, "would_change_decision": change,
                              "drafted_by": "template"}
    return rated


# --- entry point -------------------------------------------------------------

def run(cve_id, snapshot_path=None, llm=None, faults=(), label=None, out_root="outputs",
        save=True):
    settings = load_settings()
    cfg = settings["agent"]
    faults = tuple(faults or ())
    started = _now()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + (f"_{label}" if label else "")
    trace = Trace()

    info = intake(cve_id, snapshot_path, settings)
    trace.add("intake", **info)
    llm = llm or OllamaClient(settings)
    ledger = Ledger(info["snapshot_file"], info["snapshot_id"])

    with fault_mod.inject(faults, llm):
        trace.add("faults", faults=list(faults))
        outcome = investigate(llm, info, info["snapshot_path"], ledger, trace, cfg, faults)
        threat = threat_facts(ledger)
        rated = []
        if outcome["status"] == "completed":
            rated = apply_policy(outcome["validated"], ledger, threat, outcome["submissions"])
            for item in rated:
                trace.add("policy", asset=f"{item['finding']['asset_id']} {item['finding']['instance']}",
                          decision=item["result"]["decision"], rule=item["result"]["rule"])
            rated = draft_actions(llm, rated, threat, info, trace, ledger)

    config = {
        "run_id": run_id, "label": label, "faults": list(faults),
        "model": llm.describe() if hasattr(llm, "describe") else {"provider": type(llm).__name__},
        "prompt_version": prompts.PROMPT_VERSION, "agent_limits": cfg,
        "sources": {k: settings.get(k) for k in ("nvd_base_url", "kev_url", "cache_dir",
                                                  "timeouts", "retries", "retry_wait_seconds")},
        "code_version": _git_version(), "policy": "docs/rating_policy.md v1.0",
    }
    assessment = report.build_assessment(run_id, started, _now(), info, config, outcome,
                                         ledger, threat, rated)
    run_dir = None
    if save:
        run_dir = REPO_ROOT / out_root / run_id
        report.save(run_dir, assessment, config, trace, outcome["messages"], ledger)
    return assessment, run_dir
