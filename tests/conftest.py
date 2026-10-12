"""Shared offline fixtures for the agent, policy and validation tests.

No LLM and no network: NVD and KEV answers are replayed from the raw files in
inputs/, the cache is a temp folder, and the model is a scripted stand-in.
"""
import json

import pytest
import requests

from src.config import REPO_ROOT
from src.faults import UNREACHABLE
from src.sources import _fetch, cache, nvd
from src.validation import cpe_label_for_os, detect_conflicts, nvd_index

CVE = "CVE-2026-85880"
NVD_RAW = REPO_ROOT / "inputs" / f"{CVE}_nvd_raw.json"
KEV_RAW = REPO_ROOT / "inputs" / f"{CVE}_kev_raw.json"
BASE = "environment/northbridge-v1.1.json"
VARIANTS = {
    "patched": "environment/variants/env_patched.json",
    "low_priority": "environment/variants/env_low_priority.json",
    "missing": "environment/variants/env_missing.json",
    "conflict": "environment/variants/env_conflict.json",
}


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


@pytest.fixture
def offline(tmp_path, monkeypatch):
    """Temp cache, no retry wait, and NVD/KEV replayed from inputs/. The fault URL
    (127.0.0.1:9) raises a connection error, as it would for real."""
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    settings = _fetch.load_settings()
    monkeypatch.setattr(_fetch, "load_settings", lambda: {**settings, "retry_wait_seconds": 0})
    kev_feed = {"catalogVersion": "test", "dateReleased": "test",
                "vulnerabilities": [read_json(KEV_RAW)]}

    def fake_get(url, params=None, headers=None, timeout=None):
        if url.startswith(UNREACHABLE):
            raise requests.ConnectionError("connection refused (test)")
        return FakeResponse(read_json(NVD_RAW) if "nvd" in url else kev_feed)

    monkeypatch.setattr(requests, "get", fake_get)
    return tmp_path


def nvd_data():
    data, _ = nvd.parse(read_json(NVD_RAW), CVE)
    return data


def _call(name, **args):
    return {"function": {"name": name, "arguments": args}}


def tool_results(messages):
    out = []
    for m in messages:
        if m.get("role") == "tool":
            out.append((m.get("tool_name"), json.loads(m["content"])))
    return out


def oracle_findings(messages, tamper=None):
    """Build correct findings from the tool results in the conversation, as a
    careful model would. tamper(finding) can corrupt them for negative tests."""
    nvd_res = next((r for n, r in tool_results(messages) if n == "lookup_vulnerability"
                    and r.get("data")), None)
    index = nvd_index(nvd_res["data"]) if nvd_res else None
    evidence = {}
    assets = {}
    for name, r in tool_results(messages):
        data = (r.get("data") or {}) if name == "lookup_environment" else {}
        if data.get("evidence"):
            evidence[data["evidence"]["evidence_id"]] = {"record": data["evidence"], "ref": r["ref"]}
        for m in data.get("matches", []) or []:
            assets[m["locator"]] = m["asset"]
    findings = []
    for loc, a in assets.items():
        label = cpe_label_for_os(a["os"])
        affected = index is not None and label in index
        if index is not None and not affected and label is None:
            continue
        fixed = next(iter(index[label]["fixed_builds"])) if affected and index[label]["fixed_builds"] else None
        build = a["os"].get("build")
        below = None
        if affected and fixed and build:
            below = tuple(map(int, build.split("."))) < tuple(map(int, fixed.split(".")))
        f = {"locator": loc, "asset_id": a["asset_id"], "instance": a["instance"],
             "os_name": a["os"]["name"], "os_build": build,
             "affected_product": f"microsoft {label}" if affected else None,
             "fixed_build": fixed, "build_below_fixed": below,
             "low_priv_local_access": a.get("low_priv_local_access"),
             "evidence_checked": a.get("evidence_ids", []),
             "conflicts": [{"evidence_id": c["evidence_id"], "detail": c["detail"]}
                           for c in detect_conflicts(a, evidence)],
             "notes": "scripted"}
        if tamper:
            f = tamper(f)
        findings.append(f)
    return {"findings": findings, "summary": "scripted oracle"}


class ScriptedLLM:
    """Stand-in model that follows a fixed plan. Each plan step is either a list
    of tool calls, the string "SUBMIT" (oracle findings), a callable
    messages -> list of calls, or a dict message to return as-is."""

    def __init__(self, plan=None, tamper=None, fail=False):
        self.plan = list(plan if plan is not None else DEFAULT_PLAN)
        self.tamper = tamper
        self.fail = fail
        self.calls = 0
        self.seen = []

    def describe(self):
        return {"provider": "scripted-test-model"}

    def chat(self, messages, tools=None, json_mode=False):
        from src.llm import LLMError
        self.calls += 1
        self.seen.append(json.dumps(messages))
        if self.fail:
            raise LLMError("scripted outage")
        if json_mode:
            return {"role": "assistant", "content": "{}"}
        if not self.plan:
            return {"role": "assistant", "content": "done"}
        step = self.plan.pop(0)
        if isinstance(step, dict):
            return step
        if step == "SUBMIT":
            step = [_call("submit_findings", **oracle_findings(messages, self.tamper))]
        elif callable(step):
            step = step(messages)
        return {"role": "assistant", "content": "", "tool_calls": step}


DEFAULT_PLAN = [
    [_call("lookup_vulnerability", cve_id=CVE)],
    [_call("lookup_kev", cve_id=CVE)],
    [_call("lookup_environment", action="search_assets", query="Windows", limit=50)],
    [_call("lookup_environment", action="get_evidence", query=f"S0{i}") for i in range(1, 9)],
    "SUBMIT",
]

call = _call
