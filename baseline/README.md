# Assignment 3 baseline (frozen for Assignment 4)

Frozen on 2026-10-12 from the final live check run `outputs/checks_20261012T185021Z`.

| Item | Value |
|---|---|
| Code | commit `860090785513dace0642dd033c87df5b0fd7b998` (no uncommitted changes in `src/`, `config/`, `environment/`) |
| Model | `gpt-oss:120b` on Ollama Cloud, temperature 0, seed 42, think medium, prompt v1.1 |
| Threat | CVE-2026-85880; NVD and CISA KEV fetched live on 2026-10-12 (copies in `inputs/`) |
| Environment | `northbridge-v1.1` (simulated) and the four test variants (copies in `inputs/`) |
| Result | W15 **High** (`P1 x High = High; KEV +1 -> High`, confidence Medium); W02 CA-ROOT01 Medium; E02 stale sensors INSUFFICIENT_EVIDENCE; 20 others Low. All 8 checks passed |

| Path | Contents |
|---|---|
| `main_run/` | The complete main run: `assessment.json`, `report.md`, `trace.jsonl`, `tool_results.json`, `messages.json`, `config.json` |
| `checks/` | Expected vs actual for every policy check and controlled failure (`summary.md`, `summary.json`). The individual runs are in `outputs/checks_20261012T185021Z/` |
| `inputs/` | Exact inputs used: raw NVD and KEV records, cache files, environment snapshot and variants, settings, requirements, expected results (path separators written as `__`) |
| `manifest.json` | SHA-256 of every file here, code version, model settings, Python version and `pip freeze` |

To reproduce: check out the commit above, install `requirements.txt`, set `OLLAMA_API_KEY`, and run `python -m src.run_checks`. The model is not fully deterministic, so tool-call order and the number of validation rounds may differ. The decisions should not, because they are computed by code from validated tool data.
