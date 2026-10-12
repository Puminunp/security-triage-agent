"""Unit tests for the output validator's deterministic helpers."""
from conftest import nvd_data
from src.validation import _query_covers, cpe_label_for_os, detect_conflicts, nvd_index


def test_cpe_labels():
    assert cpe_label_for_os({"name": "Windows Server 2016", "version": "1607"}) == "windows_server_2016"
    assert cpe_label_for_os({"name": "Windows 10 Enterprise", "version": "22H2"}) == "windows_10_22h2"
    assert cpe_label_for_os({"name": "Windows 11 Enterprise", "version": "24H2"}) == "windows_11_24h2"
    assert cpe_label_for_os({"name": "Windows Server 2012 R2", "version": None}) == "windows_server_2012 r2"
    assert cpe_label_for_os({"name": "Ubuntu Server", "version": "24.04 LTS"}) is None


def test_nvd_index_has_fixed_builds():
    idx = nvd_index(nvd_data())
    assert idx["windows_server_2016"]["fixed_builds"] == {"10.0.14393.9512"}
    assert idx["windows_10_22h2"]["fixed_builds"] == {"10.0.19045.7725"}
    assert idx["windows_server_2012"]["fixed_builds"] == set()  # NVD has no fixed build
    assert "windows_11_24h2" not in idx


def test_search_coverage():
    assert _query_covers("Windows 10", "windows_10_22h2")
    assert _query_covers("Windows Server", "windows_server_2012 r2")
    assert _query_covers("windows", "windows_server_2016")
    assert not _query_covers("Windows Server 2022", "windows_server_2016")


def test_conflict_detection():
    rec = {"asset_id": "W15", "os": {"build": "10.0.14393.9339"}}
    agree = {"S08": {"ref": "R1", "record": {"facts": ["W15: build 10.0.14393.9339 (July)"]}}}
    disagree = {"S08": {"ref": "R1", "record": {"facts": ["W15: build 10.0.14393.9512 (Sept)"]}}}
    assert detect_conflicts(rec, agree) == []
    assert detect_conflicts(rec, disagree)[0]["evidence_id"] == "S08"
    assert detect_conflicts({"asset_id": "W15", "os": {"build": None}}, disagree) == []
