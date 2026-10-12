"""End-to-end agent tests with a scripted model (no LLM, no network).

They check the orchestration, validation, stop rules and failure handling.
The live-model runs of the same checks are in outputs/checks_*/ (src/run_checks.py).
"""
import json

import pytest

from conftest import BASE, CVE, NVD_RAW, VARIANTS, ScriptedLLM, call, read_json
from src import agent
from src.sources import cache, nvd


def w15(a):
    return next(x for x in a["assessments"] if x["asset"]["asset_id"] == "W15")


def run(snapshot=BASE, llm=None, faults=(), **kw):
    a, _ = agent.run(CVE, snapshot_path=snapshot, llm=llm or ScriptedLLM(), faults=faults,
                     save=False, **kw)
    return a


# --- complete run and the three policy checks ---------------------------------

def test_main_run_rates_w15_high_with_citations(offline):
    a = run()
    assert a["run"]["status"] == "completed"
    x = w15(a)
    assert x["decision"] == "High"
    assert x["rationale"]["policy_rule"] == "P1 x High = High; KEV +1 -> High"
    assert x["confidence"]["level"] == "Medium"  # decisive facts rely on S07/S08
    tools = {e["tool"] for e in x["evidence"]}
    assert tools == {"lookup_environment", "lookup_vulnerability", "lookup_kev"}
    assert {e.get("source_mode") for e in x["evidence"]} == {"simulated", "live"}
    assert any("A15" in s for s in x["assumptions"])
    assert x["action"]["recommended_action"]


def test_secondary_scan_matches_expected(offline):
    a = run()
    got = {f"{x['asset']['asset_id']} {x['asset']['instance']}": x["decision"]
           for x in a["assessments"] if x["decision"] != "Low"}
    assert got == {"W15 FINLEG01-FINLEG02": "High", "W02 CA-ROOT01": "Medium",
                   "E02 Legacy workstations (stale sensors)": "INSUFFICIENT_EVIDENCE"}


@pytest.mark.parametrize("variant, decision, applicability, priority", [
    ("patched", "Low", "Not applicable", "P1"),                     # 1 applicability change
    ("low_priority", "Medium", "Confirmed", "P3"),                  # 2 impact change
    ("missing", "INSUFFICIENT_EVIDENCE", "Unknown", "P1"),          # 3a missing evidence
    ("conflict", "INSUFFICIENT_EVIDENCE", "Conflict", "P1"),        # 3b conflicting evidence
])
def test_policy_checks(offline, variant, decision, applicability, priority):
    x = w15(run(VARIANTS[variant]))
    assert x["decision"] == decision
    assert x["rationale"]["applicability"]["level"] == applicability
    assert x["rationale"]["impact"]["priority"] == priority


def test_conflict_output_names_both_sources(offline):
    x = w15(run(VARIANTS["conflict"]))
    conflict = x["rationale"]["applicability"]["facts"]["conflicts"][0]
    assert conflict["evidence_id"] == "S08"
    assert "9512" in conflict["detail"] and "9339" in conflict["detail"]
    assert "env_conflict.json#assets[17]" in conflict["detail"]  # real locator, not the blinded one
    assert x["status"] == "needs_analyst_review"


def test_model_never_sees_the_variant_name(offline):
    llm = ScriptedLLM()
    run(VARIANTS["conflict"], llm=llm)
    seen = " ".join(llm.seen)
    assert "env_conflict" not in seen and "conflicting_evidence" not in seen


# --- controlled failures ------------------------------------------------------

def test_4a_nvd_down_uses_cache(offline):
    cache.save(nvd.cache_key(CVE), read_json(NVD_RAW))
    a = run(faults=["nvd-down"])
    assert ("lookup_vulnerability", "cached") in [(l["tool"], l["status"]) for l in a["external_lookups"]]
    x = w15(a)
    assert x["decision"] == "High"
    assert x["confidence"]["level"] in ("Medium", "Low")
    assert "cached fallback" in x["confidence"]["reason"]


def test_4b_nvd_down_no_cache_stops_insufficient(offline):
    a = run(faults=["nvd-down-no-cache"])
    assert a["run"]["status"] == "stopped_decisive_lookup_failed"
    assert a["overall"]["decision"] == "INSUFFICIENT_EVIDENCE"
    assert "lookup_vulnerability" in a["run"]["stop_reason"]
    assert a["assessments"] == []


def test_4c_three_rejected_calls_stop_without_rating(offline):
    bad = [[call("scan_network", target="W15")],
           [call("lookup_environment", action="get_evidence", query="S08", limit=1)],
           [call("delete_asset", asset_id="W15")],
           "SUBMIT"]
    a = run(llm=ScriptedLLM(plan=bad))
    assert a["run"]["status"] == "stopped_rejected_calls"
    assert a["overall"]["decision"] is None and a["assessments"] == []
    assert a["agent_activity"]["rejected_tool_calls"] == 3


def test_4c_one_rejected_call_then_model_continues(offline):
    from conftest import DEFAULT_PLAN
    plan = [[call("scan_network", target="W15")]] + list(DEFAULT_PLAN)
    a = run(llm=ScriptedLLM(plan=plan))
    assert a["run"]["status"] == "completed"
    assert a["agent_activity"]["rejected_tool_calls"] == 1
    assert w15(a)["decision"] == "High"


def test_kev_down_uses_cached_feed(offline):
    run()  # first run fills the temp cache with the KEV feed
    a = run(faults=["kev-down"])
    assert ("lookup_kev", "cached") in [(l["tool"], l["status"]) for l in a["external_lookups"]]
    assert w15(a)["decision"] == "High"


def test_model_outage_stops_without_rating(offline):
    a = run(llm=ScriptedLLM(fail=True))
    assert a["run"]["status"] == "stopped_model_error"
    assert a["overall"]["decision"] is None


def test_text_only_replies_stop(offline):
    talk = {"role": "assistant", "content": "W15 is high risk."}
    a = run(llm=ScriptedLLM(plan=[talk, talk, talk]))
    assert a["run"]["status"] == "stopped_no_submission"
    assert a["assessments"] == []


# --- output validation --------------------------------------------------------

def _wrong_w15_build(f):
    if f["asset_id"] == "W15":
        f = {**f, "os_build": "10.0.14393.9512", "build_below_fixed": False}
    return f


def test_hallucinated_fact_is_sent_back_and_corrected(offline):
    from conftest import DEFAULT_PLAN, oracle_findings
    first = lambda m: [call("submit_findings", **oracle_findings(m, _wrong_w15_build))]
    plan = list(DEFAULT_PLAN[:-1]) + [first, "SUBMIT"]
    a = run(llm=ScriptedLLM(plan=plan))
    assert a["agent_activity"]["submissions"] == 2
    assert w15(a)["decision"] == "High"


def test_fact_that_never_validates_becomes_insufficient(offline):
    llm = ScriptedLLM(tamper=_wrong_w15_build)
    llm.plan += ["SUBMIT", "SUBMIT"]
    a = run(llm=llm)
    x = w15(a)
    assert a["agent_activity"]["submissions"] == 3
    assert x["decision"] == "INSUFFICIENT_EVIDENCE"
    assert x["validation_errors"]


def test_fixed_build_from_memory_is_rejected(offline):
    from conftest import DEFAULT_PLAN
    def no_env_but_claims(m):
        return [call("submit_findings", findings=[{
            "locator": "snapshot.json#assets[17]", "asset_id": "W15", "instance": "FINLEG01-FINLEG02",
            "os_build": "10.0.14393.9339", "affected_product": "microsoft windows_server_2016",
            "fixed_build": "10.0.14393.9512", "build_below_fixed": True,
            "low_priv_local_access": True, "conflicts": []}])]
    plan = list(DEFAULT_PLAN[:2]) + [no_env_but_claims, no_env_but_claims, no_env_but_claims]
    a = run(llm=ScriptedLLM(plan=plan))
    errors = " ".join(a["agent_activity"]["final_validation_errors"])
    assert "was not returned by any lookup_environment call" in errors
    assert "never checked in the environment" in errors
    # Unverified findings must never be reported as "Low" by omission.
    assert a["overall"]["decision"] == "INSUFFICIENT_EVIDENCE"
    assert a["overall"]["unresolved_validation_errors"]


def test_run_saves_all_artifacts(offline, tmp_path):
    a, run_dir = agent.run(CVE, llm=ScriptedLLM(), out_root=str(tmp_path / "out"), label="t")
    for name in ("assessment.json", "report.md", "trace.jsonl", "config.json", "messages.json",
                 "tool_results.json"):
        assert (run_dir / name).exists(), name
    saved = json.loads((run_dir / "assessment.json").read_text(encoding="utf-8"))
    assert saved["intake"]["snapshot_sha256"] and saved["run"]["code_version"]
    events = [json.loads(l)["event"] for l in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[0] == "intake" and "validation" in events and "policy" in events


def test_4c_bad_tool_fault_replaces_first_call_and_run_recovers(offline):
    from conftest import DEFAULT_PLAN
    # The scripted model's first call (lookup_vulnerability) is replaced, so it has to redo it.
    plan = [DEFAULT_PLAN[0]] + list(DEFAULT_PLAN)
    a = run(llm=ScriptedLLM(plan=plan), faults=["bad-tool"])
    assert a["run"]["status"] == "completed"
    assert a["agent_activity"]["rejected_tool_calls"] == 1
    assert w15(a)["decision"] == "High"
