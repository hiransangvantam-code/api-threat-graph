# results/

Everything here is produced by `bench/run_experiment.py` and `bench/report.py`. Method: `docs/EXPERIMENT.md`.

| Path | What it is |
|---|---|
| `tables.md` | all result tables in one page (start here) |
| `tables/*.csv` | the same tables as CSV, for a spreadsheet or LaTeX |
| `figures/*.png` | figures for the paper |
| `grid/<testbed>-<C1\|C2>-s<seed>/` | one of the 30 main runs |
| `overhead/` | capture overhead runs and `<testbed>-overhead.json` |
| `scale/` | volume runs and `<testbed>-scale.json` |
| `curve/` | workload-size runs and `<testbed>-curve.json` |

Inside one run folder:

| File | Content |
|---|---|
| `run.json` | condition, untraced services, workload summary, timings, and every metric for all 15 source subsets |
| `raw/*.json` | Phase 1 output (the four extractor files and `manifest.json`) |
| `capture/flows.jsonl` | what mitmproxy recorded |
| `telemetry/*.jsonl` | OpenTelemetry spans (OTLP JSON) |
| `gt/*.jsonl` | the testbed's own access logs: ground truth, never read by the extractor |
| `extractor.yaml` | the exact Phase 1 config used |
| `ports.json`, `workload.json`, `perf_*.json` | ports, load generator report, time and memory |

To rescore without rerunning: `python -c "from bench.evaluate import evaluate_run; ..."` on any run folder, or rerun `python bench/report.py`.
