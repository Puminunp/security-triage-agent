"""The demo app's data endpoints (no network, no model)."""
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from demo import server


def test_environment_matches_policy_and_baseline():
    env = server.environment("environment/northbridge-v1.1.json")
    w15 = next(a for a in env["assets"] if a["record"]["asset_id"] == "W15")
    assert w15["policy"]["decision"] == "High" and w15["priority"] == "P1"
    assert w15["agent"]["decision"] == "High"  # baseline run agrees with the policy
    for a in env["assets"]:  # every baseline decision matches the policy on the same facts
        if a["agent"]:
            assert a["agent"]["decision"] == a["policy"]["decision"], a["record"]["asset_id"]


def test_variants_change_w15_only_as_expected():
    expected = {"environment/variants/env_patched.json": "Low",
                "environment/variants/env_low_priority.json": "Medium",
                "environment/variants/env_missing.json": "INSUFFICIENT_EVIDENCE",
                "environment/variants/env_conflict.json": "INSUFFICIENT_EVIDENCE"}
    for path, decision in expected.items():
        w15 = next(a for a in server.environment(path)["assets"] if a["record"]["asset_id"] == "W15")
        assert w15["policy"]["decision"] == decision, path


def test_rate_endpoint_uses_policy():
    r = server.rate({"asset": {"affected": True, "fixed_build": "10.0.14393.9512",
                               "os_build": "10.0.14393.9339", "low_priv_local_access": True,
                               "exposure": "intranet", "data_classification": "restricted_pii",
                               "data_protection": "unprotected", "conflicts": []},
                     "threat": {"cvss_score": 7.8, "in_kev": True}})
    assert r["decision"] == "High" and r["confidence"] == "Medium"


def test_saved_baseline_run_and_path_guard():
    run = server.saved_run("baseline/main_run")
    assert run["assessment"]["overall"]["decision"] == "High"
    assert any(e.get("preview") for e in run["events"] if e["event"] == "tool_call")
    with pytest.raises(ValueError):
        server.saved_run("../../etc")
    with pytest.raises(ValueError):
        server.environment("/etc/passwd")


def test_http_serves_page_and_rejects_unknown_tool():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        assert b"Security Triage Agent" in urllib.request.urlopen(base + "/").read()
        req = urllib.request.Request(base + "/api/tool", method="POST",
                                     data=json.dumps({"name": "scan_network", "args": {}}).encode(),
                                     headers={"Content-Type": "application/json"})
        body = json.loads(urllib.request.urlopen(req).read())
        assert body["result"]["status"] == "error" and "unknown tool" in body["result"]["error"]
    finally:
        httpd.shutdown()


def test_review_marks_and_signoff_are_saved(tmp_path, monkeypatch):
    doc = tmp_path / "evidence_review.md"
    doc.write_text(server.REVIEW_DOC.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(server, "REVIEW_DOC", doc)
    st = server.review_state()
    assert len(st["items"]) == 19 and {s["name"] for s in st["signoff"]} == {"Paul Prommark", "Supawich Puengdang"}
    server.review_mark({"id": "A11", "verdict": "issue", "note": "step 3 | misreads the config"})
    server.review_mark({"id": "C4", "verdict": "ok", "note": ""})
    server.review_signoff({"name": "Paul Prommark", "date": "2026-10-14", "result": "Agree"})
    st = server.review_state()
    rows = {i["id"]: i["review"] for i in st["items"]}
    assert rows["A11"] == "⚠️ step 3 / misreads the config" and rows["C4"] == "✅"
    assert st["signoff"][0] == {"name": "Paul Prommark", "date": "2026-10-14", "result": "Agree"}
    with pytest.raises(ValueError):
        server.review_mark({"id": "A1", "verdict": "maybe"})


def test_every_review_claim_has_sources():
    for item in server.review_state()["items"]:
        assert server.review_sources(item["id"])["sources"], item["id"]
