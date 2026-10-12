"""Tool tests. No LLM, and no network unless RUN_LIVE=1.

NVD and KEV responses are replayed from the raw files in inputs/. The cache
always points at a temporary directory, so the real cache/ is never touched.
"""
import json
import os
import shutil

import pytest
import requests

from src.config import REPO_ROOT
from src.sources import _fetch, cache, kev, nvd
from src.tools import environment, registry

CVE = "CVE-2026-85880"
NVD_RAW = REPO_ROOT / "inputs" / f"{CVE}_nvd_raw.json"
KEV_RAW = REPO_ROOT / "inputs" / f"{CVE}_kev_raw.json"
VARIANTS = REPO_ROOT / "environment" / "variants"
UNREACHABLE = "http://127.0.0.1:9/unreachable"  # nothing listens on port 9

live = pytest.mark.skipif(os.getenv("RUN_LIVE") != "1", reason="set RUN_LIVE=1 for live calls")


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


@pytest.fixture(autouse=True)
def temp_cache(tmp_path, monkeypatch):
    """Send all cache reads and writes to a temporary directory; skip the retry wait."""
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    settings = _fetch.load_settings()
    monkeypatch.setattr(_fetch, "load_settings", lambda: {**settings, "retry_wait_seconds": 0})
    return tmp_path / "cache"


@pytest.fixture
def replay(monkeypatch):
    """Answer requests.get from the raw files in inputs/ instead of the network."""
    kev_feed = {"catalogVersion": "test", "dateReleased": "test",
                "vulnerabilities": [read_json(KEV_RAW)]}

    def fake_get(url, params=None, headers=None, timeout=None):
        return FakeResponse(read_json(NVD_RAW) if "nvd" in url else kev_feed)

    monkeypatch.setattr(requests, "get", fake_get)


def only_asset(result):
    assert result["status"] == "ok"
    assert len(result["data"]["matches"]) == 1
    return result["data"]["matches"][0]


# --- cache ---

def test_cache_save_and_load(temp_cache):
    assert cache.load("thing") is None
    stamp = cache.save("thing", {"a": 1})
    assert cache.load("thing") == {"a": 1}
    stored = read_json(temp_cache / "thing.json")
    assert stored["retrieved_at"] == stamp
    with pytest.raises(ValueError):
        cache.save("../outside", {})


# --- NVD ---

def check_nvd(result):
    data = result["data"]
    assert data["cvss_v31"]["base_score"] == 7.8
    assert data["cvss_v31"]["vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert data["cvss_v31"]["score_used"] == "cna_secondary"
    assert data["kev"]["in_kev"] is True
    assert data["kev"]["cisaExploitAdd"] == "2026-09-08"
    assert data["kev"]["cisaActionDue"] == "2026-09-22"
    assert data["kev"]["cisaRequiredAction"]
    assert data["cwe"] == ["CWE-122", "CWE-908"]
    fixed = {p["cpe"].split(":")[4]: p["versionEndExcluding"] for p in data["affected_products"]
             if p["cpe"].split(":")[5] == "*"}
    assert fixed["windows_server_2016"] == "10.0.14393.9512"
    assert fixed["windows_server_2022"] == "10.0.20348.5622"
    assert any("msrc.microsoft.com" in r["url"] for r in data["references"])
    # Server 2012 CPEs carry no fixed build: reported as unknown, not guessed.
    assert any(f.endswith(".versionEndExcluding") for f in result["unknown_fields"])


def test_nvd_fields(replay, temp_cache):
    result = nvd.fetch_cve(CVE)
    assert result["status"] == "live"
    check_nvd(result)
    assert (temp_cache / f"nvd_{CVE}.json").exists()


def test_nvd_prefers_primary_score():
    metrics = {"cvssMetricV31": [
        {"type": "Secondary", "source": "cna", "cvssData": {"baseScore": 7.8}},
        {"type": "Primary", "source": "nvd@nist.gov", "cvssData": {"baseScore": 8.8}},
    ]}
    picked = nvd._cvss_v31(metrics)
    assert picked["base_score"] == 8.8 and picked["score_used"] == "nvd_primary"
    assert nvd._cvss_v31({}) is None


def test_nvd_unknown_cve_is_not_found(replay):
    result = nvd.fetch_cve("CVE-2026-0001")
    assert result["status"] == "not_found"


def test_nvd_sends_api_key_only_when_set(monkeypatch):
    seen = []

    def fake_get(url, params=None, headers=None, timeout=None):
        seen.append((headers, timeout))
        return FakeResponse(read_json(NVD_RAW))

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    nvd.fetch_cve(CVE)
    monkeypatch.setenv("NVD_API_KEY", "dummy-test-value")
    nvd.fetch_cve(CVE)
    assert seen[0] == (None, 15)
    assert seen[1] == ({"apiKey": "dummy-test-value"}, 15)


# --- KEV ---

def test_kev_listed(replay, temp_cache):
    result = kev.fetch_kev_entry(CVE)
    assert result["status"] == "live"
    assert result["data"]["in_kev"] is True
    assert result["data"]["entry"]["dateAdded"] == "2026-09-08"
    assert (temp_cache / "kev_feed.json").exists()  # the whole feed is cached


def test_kev_not_listed(replay):
    result = kev.fetch_kev_entry("CVE-2026-0001")
    assert result["status"] == "live"
    assert result["data"]["in_kev"] is False
    assert result["data"]["entry"] is None
    assert result["data"]["note"] == "absence from KEV does not establish safety"


# --- failure behavior: retry once, then cache, then error ---

def test_nvd_unreachable_returns_cached_copy(temp_cache):
    cache.save(f"nvd_{CVE}", read_json(NVD_RAW))
    result = nvd.fetch_cve(CVE, base_url=UNREACHABLE)
    assert result["status"] == "cached"
    assert result["error"]  # the reason the live call failed is kept
    check_nvd(result)


def test_nvd_unreachable_without_cache_is_error(temp_cache):
    cache.save(f"nvd_{CVE}", read_json(NVD_RAW))
    (temp_cache / f"nvd_{CVE}.json").unlink()
    result = nvd.fetch_cve(CVE, base_url=UNREACHABLE)
    assert result["status"] == "error"
    assert result["data"] is None
    assert "no cached copy" in result["error"]


def test_failed_lookup_is_retried_once(monkeypatch):
    calls = []

    def failing_get(url, **kwargs):
        calls.append(url)
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "get", failing_get)
    assert nvd.fetch_cve(CVE)["status"] == "error"
    assert len(calls) == 2


def test_kev_unreachable_cached_then_error(temp_cache):
    cache.save("kev_feed", {"vulnerabilities": [read_json(KEV_RAW)]})
    result = kev.fetch_kev_entry(CVE, url=UNREACHABLE)
    assert result["status"] == "cached" and result["data"]["in_kev"] is True
    (temp_cache / "kev_feed.json").unlink()
    result = kev.fetch_kev_entry(CVE, url=UNREACHABLE)
    assert result["status"] == "error" and result["data"] is None


def test_bad_response_is_not_cached(monkeypatch, temp_cache):
    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResponse({"message": "nope"}))
    assert nvd.fetch_cve(CVE)["status"] == "error"
    assert not (temp_cache / f"nvd_{CVE}.json").exists()


# --- environment: base snapshot ---

def test_get_asset_w15_base():
    result = environment.get_asset("W15")
    match = only_asset(result)
    asset = match["asset"]
    assert asset["os"]["build"] == "10.0.14393.9339"
    assert asset["data_classification"] == "restricted_pii"
    assert asset["low_priv_local_access"] is True
    assert result["source_mode"] == "simulated"
    assert result["snapshot_id"] == "northbridge-v1.1"
    assert result["locator"] == "northbridge-v1.1.json#assets[17]"


def test_get_asset_returns_record_exactly_as_stored():
    stored = read_json(REPO_ROOT / "environment" / "northbridge-v1.1.json")["assets"][17]
    assert only_asset(environment.get_asset("W15"))["asset"] == stored
    handoff_fields = {"asset_id", "instance", "count", "role", "zone", "os", "software",
                      "data_classification", "data_protection", "exposure", "priority_override",
                      "low_priv_local_access", "business_service", "controls", "config",
                      "evidence_ids", "notes", "source_mode"}
    assert handoff_fields <= set(stored)


def test_get_asset_by_instance_and_hostname():
    for query in ("FINLEG01-FINLEG02", "finleg02", "w15"):
        assert only_asset(environment.get_asset(query))["asset"]["asset_id"] == "W15"
    assert environment.get_asset("FINLEG03")["status"] == "not_found"


def test_get_asset_id_with_several_records():
    result = environment.get_asset("E02")
    assert len(result["data"]["matches"]) == 2
    stale = result["data"]["matches"][1]
    assert "os.build" in stale["unknown_fields"]
    assert "assets[27].os.build" in result["unknown_fields"]


def test_search_assets():
    result = environment.search_assets("Windows Server 2016")
    assert only_asset(result)["asset"]["asset_id"] == "W15"
    limited = environment.search_assets("Windows Server 2022", limit=2)
    assert len(limited["data"]["matches"]) == 2
    assert limited["data"]["total_matches"] > 2


def test_search_assets_no_match():
    result = environment.search_assets("nonexistent")
    assert result["status"] == "not_found"
    assert result["note"] == "no match does not prove absence; only check_absence can"
    assert result["source_mode"] == "simulated"


def test_check_absence():
    result = environment.check_absence("Kubernetes")
    assert result["status"] == "ok" and result["data"]["absent"] is True
    assert environment.check_absence("kubernetes")["data"]["absent"] is True
    # A partial name must not be read as a documented absence.
    partial = environment.check_absence("Windows")
    assert partial["status"] == "not_found"
    assert partial["data"]["absent"] is None
    assert "absent" in partial["unknown_fields"]


def test_get_evidence_flows_and_business_service():
    ev = environment.get_evidence("S08")
    assert ev["status"] == "ok" and ev["locator"] == "northbridge-v1.1.json#evidence[7]"
    assert environment.get_evidence("S99")["status"] == "not_found"

    flows = environment.get_flows("LEGACY")
    assert [f["flow_id"] for f in flows["data"]["inbound"]] == ["F07"]
    assert flows["data"]["default_policy"]
    assert environment.get_flows("NOWHERE")["status"] == "not_found"

    svc = environment.get_business_service("payroll_legacy_finance")
    assert svc["data"]["business_service"]["rto"] == "8h"
    assert environment.get_business_service("nope")["status"] == "not_found"


@pytest.mark.parametrize("func", [
    environment.get_asset, environment.search_assets, environment.get_evidence,
    environment.get_flows, environment.check_absence, environment.get_business_service,
])
@pytest.mark.parametrize("bad", ["", "   ", None, 15, ["W15"]])
def test_environment_empty_or_invalid_input_is_error(func, bad):
    result = func(bad)
    assert result["status"] == "error" and result["error"]


def test_environment_bad_limit_and_missing_snapshot():
    assert environment.search_assets("Windows", limit=0)["status"] == "error"
    assert environment.search_assets("Windows", limit="5")["status"] == "error"
    assert environment.get_asset("W15", snapshot_path="no/such/file.json")["status"] == "error"


# --- environment: variants ---

def test_variant_missing_build_is_null_and_unknown():
    result = environment.get_asset("W15", snapshot_path=VARIANTS / "env_missing.json")
    match = only_asset(result)
    assert match["asset"]["os"]["build"] is None
    assert "os.build" in match["unknown_fields"]
    assert "assets[17].os.build" in result["unknown_fields"]
    assert result["locator"] == "env_missing.json#assets[17]"
    assert result["snapshot_id"] == "northbridge-v1.1-missing_evidence"


def test_variant_conflict_evidence_disagrees_with_asset():
    path = VARIANTS / "env_conflict.json"
    facts = environment.get_evidence("S08", snapshot_path=path)["data"]["evidence"]["facts"]
    w15_lines = [f for f in facts if f.startswith("W15")]
    assert w15_lines and "9512" in w15_lines[0]
    asset = only_asset(environment.get_asset("W15", snapshot_path=path))["asset"]
    assert asset["os"]["build"] == "10.0.14393.9339"


def test_variant_patched():
    asset = only_asset(environment.get_asset("W15", snapshot_path=VARIANTS / "env_patched.json"))
    assert asset["asset"]["os"]["build"] == "10.0.14393.9512"


# --- registry ---

WRAPPER_KEYS = {"tool", "args", "status", "source", "retrieved_at", "source_mode",
                "data", "unknown_fields", "error"}


def test_schemas():
    names = [s["name"] for s in registry.TOOL_SCHEMAS]
    assert names == ["lookup_vulnerability", "lookup_kev", "lookup_environment"]
    for schema in registry.TOOL_SCHEMAS:
        assert schema["description"] and schema["parameters"]["type"] == "object"
    env = registry.TOOL_SCHEMAS[2]["parameters"]["properties"]["action"]["enum"]
    assert env == ["get_asset", "search_assets", "get_evidence", "get_flows",
                   "check_absence", "get_business_service"]


@pytest.mark.parametrize("tool,args", [
    ("no_such_tool", {"cve_id": CVE}),                                  # unknown tool
    (None, {}),
    ("lookup_vulnerability", {"cve_id": "CVE-123"}),                    # bad CVE ID
    ("lookup_kev", {"cve_id": "cve-2026-85880"}),
    ("lookup_kev", {"cve_id": CVE + "\n"}),
    ("lookup_vulnerability", {}),                                       # missing args
    ("lookup_environment", {"action": "get_asset"}),
    ("lookup_environment", {"query": "W15"}),
    ("lookup_environment", {"action": "delete_asset", "query": "W15"}),  # wrong args
    ("lookup_environment", {"action": "get_asset", "query": ""}),
    ("lookup_environment", {"action": "get_asset", "query": 15}),
    ("lookup_environment", {"action": "get_asset", "query": "W15", "limit": 5}),
    ("lookup_environment", {"action": "search_assets", "query": "x", "limit": 0}),
    ("lookup_environment", {"action": "get_asset", "query": "W15", "snapshot_path": "x"}),
    ("lookup_vulnerability", "CVE-2026-85880"),
    ("lookup_vulnerability", None),
])
def test_registry_rejects_bad_calls(tool, args, monkeypatch):
    def no_network(*a, **kw):
        raise AssertionError("a rejected call must not reach the network")

    monkeypatch.setattr(requests, "get", no_network)
    result = registry.execute(tool, args)
    assert set(result) == WRAPPER_KEYS
    assert result["status"] == "error" and result["error"]
    assert result["data"] is None


def test_registry_environment_call():
    result = registry.execute("lookup_environment", {"action": "get_asset", "query": "W15"})
    assert set(result) == WRAPPER_KEYS
    assert result["status"] == "ok"
    assert result["source_mode"] == "simulated"
    assert result["source"] == "northbridge-v1.1.json#assets[17]"
    assert result["data"]["snapshot_id"] == "northbridge-v1.1"
    assert result["data"]["locator"] == "northbridge-v1.1.json#assets[17]"
    assert result["data"]["matches"][0]["asset"]["os"]["build"] == "10.0.14393.9339"
    assert result["retrieved_at"]


def test_registry_environment_variant_and_not_found():
    args = {"action": "get_asset", "query": "W15"}
    result = registry.execute("lookup_environment", args,
                              snapshot_path=VARIANTS / "env_missing.json")
    assert "assets[17].os.build" in result["unknown_fields"]

    result = registry.execute("lookup_environment",
                              {"action": "search_assets", "query": "nonexistent"})
    assert result["status"] == "not_found"
    assert result["data"]["note"] == "no match does not prove absence; only check_absence can"


def test_registry_source_calls(replay):
    result = registry.execute("lookup_vulnerability", {"cve_id": CVE})
    assert set(result) == WRAPPER_KEYS
    assert (result["status"], result["source_mode"]) == ("live", "live")
    assert result["source"].endswith(f"?cveId={CVE}")
    check_nvd(result)

    result = registry.execute("lookup_kev", {"cve_id": CVE})
    assert (result["status"], result["source_mode"]) == ("live", "live")
    assert result["data"]["entry"]["dateAdded"] == "2026-09-08"


def test_registry_cached_and_error_modes(monkeypatch, temp_cache):
    def down(url, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "get", down)
    cache.save(f"nvd_{CVE}", read_json(NVD_RAW))
    result = registry.execute("lookup_vulnerability", {"cve_id": CVE})
    assert (result["status"], result["source_mode"]) == ("cached", "cached")
    assert result["data"]["cvss_v31"]["base_score"] == 7.8

    shutil.rmtree(temp_cache)
    result = registry.execute("lookup_vulnerability", {"cve_id": CVE})
    assert result["status"] == "error" and result["data"] is None and result["error"]


# --- live checks against the real services (RUN_LIVE=1) ---

@live
def test_live_nvd():
    result = nvd.fetch_cve(CVE)
    assert result["status"] == "live"
    check_nvd(result)


@live
def test_live_kev():
    result = kev.fetch_kev_entry(CVE)
    assert result["status"] == "live"
    assert result["data"]["in_kev"] is True
    assert result["data"]["entry"]["dateAdded"] == "2026-09-08"
