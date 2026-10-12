"""Controlled failures for testing (docs/test_results.md, checks 4a-4d).

Each fault breaks one real dependency so the normal failure path runs: the
source clients really fail to connect, really retry and really fall back to
the cache. Nothing is mocked inside Student B's retry/cache logic.

    nvd-down            NVD URL points at a closed port; the cached NVD record is used
    nvd-down-no-cache   as above, and the cache directory is an empty temp folder
    kev-down            KEV feed URL points at a closed port; the cached feed is used
    bad-tool            the model's first tool call is replaced by a call to a tool that
                        does not exist (scan_network), as if the model had hallucinated it
    llm-down            the model endpoint points at a closed port
"""
import contextlib
import functools
import tempfile
from pathlib import Path

from src.sources import cache, kev, nvd

UNREACHABLE = "http://127.0.0.1:9/unreachable"  # nothing listens on port 9

FAULTS = ("nvd-down", "nvd-down-no-cache", "kev-down", "bad-tool", "llm-down")

BAD_TOOL_CALL = {"function": {"name": "scan_network", "arguments": {"target": "W15"}}}


@contextlib.contextmanager
def inject(faults, llm=None):
    faults = set(faults or ())
    unknown = faults - set(FAULTS)
    if unknown:
        raise ValueError(f"unknown fault(s): {', '.join(sorted(unknown))}")
    saved = {"nvd": nvd.fetch_cve, "kev": kev.fetch_kev_entry, "cache": cache.CACHE_DIR,
             "llm": getattr(llm, "base_url", None)}
    tmp = None
    try:
        if faults & {"nvd-down", "nvd-down-no-cache"}:
            nvd.fetch_cve = functools.partial(saved["nvd"], base_url=UNREACHABLE)
        if "nvd-down-no-cache" in faults:
            tmp = tempfile.TemporaryDirectory(prefix="empty-cache-")
            cache.CACHE_DIR = Path(tmp.name)
        if "kev-down" in faults:
            kev.fetch_kev_entry = functools.partial(saved["kev"], url=UNREACHABLE)
        if "llm-down" in faults and llm is not None and hasattr(llm, "base_url"):
            llm.base_url = UNREACHABLE
        yield
    finally:
        nvd.fetch_cve = saved["nvd"]
        kev.fetch_kev_entry = saved["kev"]
        cache.CACHE_DIR = saved["cache"]
        if saved["llm"] is not None:
            llm.base_url = saved["llm"]
        if tmp:
            tmp.cleanup()
