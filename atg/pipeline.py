"""
Full pipeline, Phases 1-4:

    python -m atg --config extractor.yaml                 # extract + analyze (target must be running)
    python -m atg --config extractor.yaml --skip-extract  # re-analyze the last output/raw

Outputs
    output/raw/*.json              Phase 1 raw API data  (+ output/report.html)
    output/eujf.json               Phase 2 Extended Universal JSON Format
    output/analysis.json           Phase 3 findings, attack paths, plan, graph
    output/dashboard.html          Phase 4 dashboard  (latest run)
    output/runs/<run_id>/...       the same three files, kept per run
    graph store (atg_* tables)     sqlite:///output/atg.db by default, or PostgreSQL

Graph store: set `graph_store:` in the config or the ATG_GRAPH_STORE environment
variable, e.g. postgresql://atg:atg@localhost:5432/atg
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from pathlib import Path

import yaml

from .analysis import analyze
from .dashboard import build_dashboard
from .graphstore import GraphStore
from .normalizer import normalize


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=list), encoding="utf-8")


def run(config, extract: bool = True, label: str | None = None, quiet: bool = False) -> dict:
    cfg = config if isinstance(config, dict) else yaml.safe_load(Path(config).read_text(encoding="utf-8"))
    raw_dir = Path(cfg.get("output_dir", "output/raw"))
    out = raw_dir.parent
    say = (lambda *a: None) if quiet else print
    timings = {}

    if extract:
        say("Phase 1 - Extractor")
        from extractor.run import run as extract_run
        t = time.perf_counter()
        extract_run(cfg)
        timings["phase1_ms"] = (time.perf_counter() - t) * 1000

    say("Phase 2 - API Normalizer")
    store = GraphStore(os.environ.get("ATG_GRAPH_STORE") or cfg.get("graph_store") or f"sqlite:///{out / 'atg.db'}")
    t = time.perf_counter()
    eujf = normalize(raw_dir)
    timings["phase2_ms"] = (time.perf_counter() - t) * 1000
    _write(out / "eujf.json", eujf)
    stored = store.save_eujf(eujf)  # the API inventory, persisted in the graph store's database
    inv, conf = eujf["summary"]["inventory"], eujf["summary"]["confidence"]
    say(f"  [ok]   {eujf['summary']['endpoints']} endpoints in {eujf['summary']['services']} services "
        f"({', '.join(f'{v} {k}' for k, v in sorted(inv.items()))})  -> {out / 'eujf.json'}")
    say(f"         EUJF confidence: HIGH {conf['HIGH']}, MEDIUM {conf['MEDIUM']}, ZOMBIE {conf['ZOMBIE']}; "
        f"{stored} records -> table atg_eujf ({store.label})")

    say("Phase 3 - Analysis & risk assessment")
    t = time.perf_counter()
    analysis = analyze(eujf, store)
    timings["phase3_ms"] = (time.perf_counter() - t) * 1000
    s = analysis["summary"]
    s["label"] = label or cfg.get("label")
    # analyze() already stored the summary; store it again with the label for the trend chart
    store.conn.cursor().execute(store._q("UPDATE atg_runs SET summary = ? WHERE run_id = ?"),
                                (json.dumps(s), analysis["run_id"]))
    store.conn.commit()
    _write(out / "analysis.json", analysis)
    sev = s["by_severity"]
    say(f"  [ok]   {s['findings']} findings (critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, "
        f"low {sev['low']}), {s['attack_paths']} attack paths, path risk {s['total_path_risk']:g}")
    say(f"         graph store: {store.label}")

    say("Phase 4 - Dashboard")
    t = time.perf_counter()
    history = store.history(eujf["target"])
    dash = out / "dashboard.html"
    timings["phase4_ms"] = 0
    build_dashboard(analysis, eujf, history, dash, timings)
    timings["phase4_ms"] = (time.perf_counter() - t) * 1000
    build_dashboard(analysis, eujf, history, dash, timings)  # again, now with its own timing
    run_dir = out / "runs" / analysis["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    for name in ("eujf.json", "analysis.json"):
        shutil.copy(out / name, run_dir / name)
    build_dashboard(analysis, eujf, history, run_dir / "dashboard.html", timings, phase1_report=None)
    _write(run_dir / "timings.json", timings)
    store.close()
    say(f"  [ok]   dashboard -> {dash}")
    return {"analysis": analysis, "eujf": eujf, "timings": timings, "dashboard": str(dash)}


def rebuild(run_dir: str, config=None) -> str:
    """Rebuild a stored run's dashboard with the latest history (e.g. after a later run)."""
    cfg = config if isinstance(config, dict) else yaml.safe_load(Path(config or "extractor.yaml").read_text(encoding="utf-8"))
    run_dir = Path(run_dir)
    out = Path(cfg.get("output_dir", "output/raw")).parent
    analysis = json.loads((run_dir / "analysis.json").read_text(encoding="utf-8"))
    eujf = json.loads((run_dir / "eujf.json").read_text(encoding="utf-8"))
    timings = json.loads((run_dir / "timings.json").read_text(encoding="utf-8")) if (run_dir / "timings.json").exists() else {}
    store = GraphStore(os.environ.get("ATG_GRAPH_STORE") or cfg.get("graph_store") or f"sqlite:///{out / 'atg.db'}")
    history = store.history(eujf["target"])
    store.close()
    return build_dashboard(analysis, eujf, history, run_dir / "dashboard.html", timings, phase1_report=None)


def main():
    ap = argparse.ArgumentParser(description="API Threat Graph - full pipeline (Phases 1-4)")
    ap.add_argument("--config", default="extractor.yaml")
    ap.add_argument("--skip-extract", action="store_true", help="reuse output/raw from the last extraction")
    ap.add_argument("--label", help="name for this run in the trend chart, e.g. 'before fix'")
    a = ap.parse_args()
    run(a.config, extract=not a.skip_extract, label=a.label)


if __name__ == "__main__":
    main()
