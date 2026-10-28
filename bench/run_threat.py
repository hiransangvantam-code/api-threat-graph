"""
Phase 2-4 experiments on top of the Phase 1 runs (run bench/run_experiment.py first).

  python bench/run_threat.py grid       [--tag NAME]   tool vs oracle threat model, every grid run
  python bench/run_threat.py hardened                   ShopLite after the fixes vs before
  python bench/run_threat.py stores                     SQLite vs PostgreSQL graph store
  python bench/run_threat.py dashboards                 Phase 4 dashboards, one per testbed and condition

Writes results/grid/<run>/threat[-TAG].json, results/hardened/hardened.json,
results/stores.json and results/dashboards/*.html.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench.evaluate_threat import evaluate_hardened, evaluate_threat_run  # noqa: E402

RES = ROOT / "results"


def grid(a):
    runs = sorted((RES / "grid").glob("*/run.json"))
    name = f"threat-{a.tag}.json" if a.tag else "threat.json"
    for f in runs:
        d = f.parent
        if a.only and not d.name.startswith(a.only):
            continue
        if (d / name).exists() and not a.force:
            continue
        tb, _, seed = d.name.split("-")
        t0 = time.time()
        r = evaluate_threat_run(tb, d, RES / "grid" / f"{tb}-C1-{seed}")
        (d / name).write_text(json.dumps(r, indent=1, default=str))
        v = r["vs_oracle"]
        print(f"{d.name:<20} findings P={v['findings']['precision']} R={v['findings']['recall']} "
              f"paths P={v['paths']['precision']} R={v['paths']['recall']} risk ratio={v['risk']['ratio']} "
              f"({time.time() - t0:.0f}s)", flush=True)


def hardened(a):
    rows = []
    for d in sorted((RES / "hardened").glob("shoplite-*")):
        r = evaluate_hardened(d, RES / "grid" / d.name)
        rows.append(r)
        print(f"{d.name}: {r['findings']} findings, R {r['R_vulnerable']} -> {r['R_hardened']} ({r['reduction_pct']}%), "
              f"as expected: {r['match_expected']}", flush=True)
    (RES / "hardened" / "hardened.json").write_text(json.dumps(rows, indent=1, default=str))


def stores(a):
    """Same EUJF into both graph stores: identical attack paths? how long does each take?"""
    from atg.analysis import analyze
    from atg.graphstore import GraphStore
    from atg.normalizer import normalize
    pg = a.pg or os.environ.get("ATG_GRAPH_STORE_PG", "postgresql://atg:atg@localhost:5432/atg")
    rows = []
    for run in ("shoplite-C1-s1", "crapi-C1-s1", "trainticket-C1-s1"):
        e = normalize(RES / "grid" / run / "raw")
        row = {"run": run}
        res = {}
        for label, url in (("sqlite", f"sqlite:///{RES / 'stores-tmp.db'}"), ("postgresql", pg)):
            reps = []
            for _ in range(a.reps):
                try:
                    store = GraphStore(url)
                except Exception as exc:  # PostgreSQL not available
                    row[label] = f"unavailable: {type(exc).__name__}"
                    break
                an = analyze(e, store)
                store.close()
                reps.append(an["timing"]["attack_path_query_ms"])
                res[label] = [(p["finding_id"], p["nodes"]) for p in an["attack_paths"]]
            if reps:
                row[label] = {"attack_path_query_ms": reps, "paths": len(res[label])}
        row["identical"] = len(res) == 2 and res["sqlite"] == res["postgresql"]
        rows.append(row)
        print(json.dumps(row), flush=True)
    (RES / "stores-tmp.db").unlink(missing_ok=True)
    (RES / "stores.json").write_text(json.dumps(rows, indent=1))


def dashboards(a):
    """The Phase 4 output for one run of each testbed and condition (seed 1)."""
    from atg.analysis import analyze
    from atg.dashboard import build_dashboard
    from atg.graphstore import GraphStore
    from atg.normalizer import normalize
    out = RES / "dashboards"
    out.mkdir(exist_ok=True)
    for tb in ("shoplite", "trainticket", "crapi"):
        for cond in ("C1", "C2"):
            run = RES / "grid" / f"{tb}-{cond}-s1"
            e = normalize(run / "raw")
            an = analyze(e, GraphStore("sqlite:///:memory:"))
            p = build_dashboard(an, e, [], out / f"{tb}-{cond}.html", an["timing"], phase1_report=None)
            print(p, flush=True)
    for run in (RES / "hardened").glob("shoplite-C1-s1"):
        e = normalize(run / "raw")
        an = analyze(e, GraphStore("sqlite:///:memory:"))
        print(build_dashboard(an, e, [], out / "shoplite-hardened-C1.html", an["timing"], phase1_report=None))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grid")
    g.add_argument("--tag", default="")
    g.add_argument("--only", default="")
    g.add_argument("--force", action="store_true")
    sub.add_parser("hardened")
    s = sub.add_parser("stores")
    s.add_argument("--pg", default="")
    s.add_argument("--reps", type=int, default=3)
    sub.add_parser("dashboards")
    a = ap.parse_args()
    {"grid": grid, "hardened": hardened, "stores": stores, "dashboards": dashboards}[a.cmd](a)


if __name__ == "__main__":
    main()
