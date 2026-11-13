"""
Stress test: how large a system can Phases 2-4 handle before they get too slow?

The EUJF of one real ShopLite scan (4 services, 12 endpoints, 37 findings) is cloned k times
behind one gateway: copy c gets its own user-service-c, order-service-c and payment-service-c
and its own route prefix /apic/. Every copy keeps the real records, so the rules fire the way
they do on ShopLite. Two experiments:

  size     k = 1 ... 100 copies, nothing else changed (4 -> 301 services)
  density  k = 10 copies plus random endpoint-to-endpoint calls across copies, d calls per
           endpoint on average. Attack paths are enumerated over CALLS chains up to 9 hops,
           so this is where the number of paths, and the time, can explode.

Each configuration runs in a fresh process (so peak memory is its own) against PostgreSQL,
the store the Docker version uses, with a time limit. Once a configuration hits the limit,
the larger ones of the same experiment are not run.

    python bench/stress.py --pg postgresql://atg:atg@localhost:55432/atg                  # this version (1.3)
    python bench/stress.py --pg postgresql://atg:atg@localhost:55432/atg --version 1.2    # as in version 1.2
    python bench/stress.py --report            # tables from results/stress/stress-*.json

Version 1.2 differs in two places, both found by this test: the fix planner scored every action
against every path at every step (bench/planner_v1.py), and the graph store did not ANALYZE the
freshly loaded tables, so PostgreSQL planned the attack path query without statistics.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import random
import re
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "results" / "stress"
BACKENDS = ("user-service", "order-service", "payment-service")
SIZES = [1, 2, 5, 10, 20, 50, 100]
DENSITY_K = 10
DENSITIES = [0, 0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 6]
TIME_LIMIT = 300


# ---------------------------------------------------------------- synthetic EUJF
def clone_eujf(base: dict, k: int, density: float = 0.0, seed: int = 1) -> dict:
    gw = base["gateway"]
    rx = re.compile(r"\b(" + "|".join(re.escape(b) for b in BACKENDS) + r")\b")
    out = copy.deepcopy(base)
    out["run_id"] = f"stress-k{k}-d{density:g}"
    out["services"] = [s for s in base["services"] if s["name"] == gw]
    out["endpoints"] = [e for e in base["endpoints"] if e["service"] == gw]
    for key in ("gateway_routes", "dependencies", "call_chains", "secrets"):
        out[key] = []
    out["entrypoints"] = [x for x in base["entrypoints"] if x["service"] == gw and "/api/" not in x["operation"]]
    out["trace_services"] = [x for x in base["trace_services"] if x["service"] == gw]
    for c in range(1, k + 1):
        s = rx.sub(lambda m: f"{m.group(1)}-{c}", json.dumps(base)).replace("/api/", f"/api{c}/")
        cl = json.loads(s)
        out["services"] += [x for x in cl["services"] if x["name"] != gw]
        out["endpoints"] += [x for x in cl["endpoints"] if x["service"] != gw]
        out["gateway_routes"] += cl["gateway_routes"]
        out["dependencies"] += cl["dependencies"]
        out["call_chains"] += cl["call_chains"]
        out["secrets"] += cl.get("secrets", [])
        out["entrypoints"] += [x for x in cl["entrypoints"] if x["service"] != gw or f"/api{c}/" in x["operation"]]
        out["trace_services"] += [x for x in cl["trace_services"] if x["service"] != gw]
    gw_svc = out["services"][0]
    gw_svc["endpoint_ids"] = [e["id"] for e in out["endpoints"] if e["service"] == gw]
    for i, e in enumerate(out["endpoints"], 1):
        e["api_id"] = f"API-{i:04d}"

    if density:
        rnd = random.Random(seed)
        backend = [e for e in out["endpoints"] if e["service"] != gw]
        n_calls = int(round(density * len(backend)))
        deps = {}
        for _ in range(n_calls):
            a, b = rnd.sample(backend, 2)
            if a["service"] == b["service"]:
                continue
            out["call_chains"].append({"traces": 1, "hops": [
                {"depth": 0, "service": a["service"], "operation": f"{a['method']} {a['path']}"},
                {"depth": 1, "service": b["service"], "operation": f"{b['method']} {b['path']}"}]})
            d = deps.setdefault((a["service"], b["service"]), {"from": a["service"], "to": b["service"], "calls": 0,
                                                                 "operations": [], "evidence": "trace"})
            d["calls"] += 1
        out["dependencies"] += list(deps.values())

    eps = out["endpoints"]
    inv = {}
    for e in eps:
        inv[e["inventory_status"]] = inv.get(e["inventory_status"], 0) + 1
    conf = {"HIGH": 0, "MEDIUM": 0, "ZOMBIE": 0}
    for e in eps:
        conf[e["evidence"]["confidence"]] = conf.get(e["evidence"]["confidence"], 0) + 1
    out["summary"] = {**base["summary"], "endpoints": len(eps), "services": len(out["services"]),
                      "inventory": inv, "confidence": conf}
    return out


# ---------------------------------------------------------------- one measured run (child process)
def child(eujf_path: str, store_url: str, out_dir: str, version: str = "1.3") -> None:
    import atg.analysis
    import atg.graphstore
    if version == "1.2":
        from bench.planner_v1 import mitigation_plan_v1
        atg.analysis.mitigation_plan = mitigation_plan_v1
        atg.graphstore.GraphStore.analyze_after_load = False
    from atg.analysis import analyze
    from atg.dashboard import build_dashboard
    from atg.export import export_all
    from atg.graphstore import GraphStore

    eujf = json.loads(Path(eujf_path).read_text(encoding="utf-8"))
    if store_url.startswith("postgresql"):  # fresh tables every run, as at the start of a Docker review
        import psycopg
        with psycopg.connect(store_url, autocommit=True) as c:
            for t in ("atg_paths", "atg_findings", "atg_edges", "atg_nodes", "atg_eujf", "atg_runs"):
                c.execute(f"DROP TABLE IF EXISTS {t}")
    t0 = time.perf_counter()
    store = GraphStore(store_url)
    t = time.perf_counter()
    store.save_eujf(eujf)
    store_eujf_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    a = analyze(eujf, store)
    phase3_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    dash = Path(out_dir) / "dashboard.html"
    build_dashboard(a, eujf, store.history(eujf["target"]), dash, {})
    phase4_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    paths = export_all(a, eujf, Path(out_dir) / "exports")
    export_ms = (time.perf_counter() - t) * 1000
    store.close()
    s = a["summary"]
    print(json.dumps({
        "services": len(eujf["services"]), "endpoints": len(eujf["endpoints"]),
        "nodes": len(a["graph"]["nodes"]), "edges": len(a["graph"]["edges"]),
        "calls_edges": sum(1 for e in a["graph"]["edges"] if e["rel"] == "CALLS"),
        "findings": s["findings"], "attack_paths": s["attack_paths"], "total_path_risk": s["total_path_risk"],
        "store_eujf_ms": round(store_eujf_ms, 1), "phase3_ms": round(phase3_ms, 1), **{k: v for k, v in a["timing"].items()},
        "phase4_ms": round(phase4_ms, 1), "export_ms": round(export_ms, 1),
        "total_ms": round((time.perf_counter() - t0) * 1000, 1),
        "dashboard_kb": round(dash.stat().st_size / 1024), "graphml_kb": round(paths["graphml"].stat().st_size / 1024),
        "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
    }))


def measure(eujf: dict, store_url: str, limit: int, version: str = "1.3") -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "eujf.json"
        p.write_text(json.dumps(eujf), encoding="utf-8")
        t = time.perf_counter()
        try:
            r = subprocess.run([sys.executable, __file__, "--child", str(p), store_url, tmp, version], capture_output=True,
                               text=True, timeout=limit, cwd=ROOT)
        except subprocess.TimeoutExpired:
            return {"services": len(eujf["services"]), "endpoints": len(eujf["endpoints"]), "timeout_s": limit}
        if r.returncode != 0:
            return {"services": len(eujf["services"]), "endpoints": len(eujf["endpoints"]),
                    "error": (r.stderr or r.stdout)[-600:], "wall_s": round(time.perf_counter() - t, 1)}
        return json.loads(r.stdout.strip().splitlines()[-1])


def run_all(raw: Path, store_url: str, limit: int, version: str) -> dict:
    import platform
    from atg.normalizer import normalize
    base = normalize(raw)
    res = {"base": str(raw.relative_to(ROOT)) if raw.is_relative_to(ROOT) else str(raw), "store": store_url.split("@")[-1],
           "version": version, "time_limit_s": limit, "cpus": os.cpu_count(), "python": platform.python_version(),
           "size": [], "density": []}
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / f"stress-{version}.json"
    for name, configs in (("size", [(k, 0) for k in SIZES]), ("density", [(DENSITY_K, d) for d in DENSITIES])):
        stop = False
        for k, d in configs:
            if stop:
                res[name].append({"k": k, "d": d, "skipped": "a smaller configuration hit the time limit"})
                continue
            r = {"k": k, "d": d, **measure(clone_eujf(base, k, d), store_url, limit, version)}
            print(name, json.dumps(r), flush=True)
            res[name].append(r)
            stop = "timeout_s" in r
            out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


# ---------------------------------------------------------------- report
def _load(version: str) -> dict | None:
    f = OUT / f"stress-{version}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


def _v(r: dict | None, key: str, limit_s: int) -> str:
    if not r:
        return "–"
    if "skipped" in r:
        return "not run"
    if "error" in r:
        if key not in ("attack_path_query_ms", "phase3_ms"):
            return "–"
        return "out of temp space" if "No space left" in r["error"] else "failed"
    if "timeout_s" in r:
        return f"> {r['timeout_s']:,} s" if key in ("phase3_ms", "total_ms") else "–"
    v = r.get(key)
    if v is None:
        return "–"
    return f"{v / 1000:,.1f} s" if key.endswith("_ms") and v >= 10000 else f"{v:,.0f}"


def report() -> None:
    new, old = _load("1.3"), _load("1.2")
    if not new:
        print("no results/stress/stress-1.3.json yet")
        return
    lim = new["time_limit_s"]
    prev = {(r["k"], r.get("d", 0)): r for r in (old or {}).get("size", []) + (old or {}).get("density", [])}
    head = ("| Path query 1.2 (ms) | Path query 1.3 (ms) | Fix plan 1.2 (ms) | Fix plan 1.3 (ms) | "
            "Phase 3 1.2 (ms) | Phase 3 1.3 (ms) |")
    lines = ["## Table 21. Stress test: system size (Phases 3-4 on PostgreSQL)", "",
             "ShopLite's EUJF (one real scan) cloned k times behind one gateway, so the rules fire as they do on ShopLite. "
             f"One run per row in a fresh process with fresh tables, stopped after {lim} s. Version 1.2 is the code before "
             "this test; 1.3 adds ANALYZE after loading the graph and the faster fix planner (same paths and same plans). "
             "Times above 10 s are in seconds.", "",
             "| Copies k | Services | Endpoints | Graph nodes | Graph edges | Findings | Attack paths " + head
             + " Phase 4 + exports 1.3 (ms) | Peak memory 1.3 (MB) | Dashboard (KB) |",
             "|" + "---|" * 16]
    for r in new["size"]:
        o = prev.get((r["k"], 0))
        p4 = "–" if "phase4_ms" not in r else f"{r['phase4_ms'] + r['export_ms']:,.0f}"
        lines.append(f"| {r['k']} | {r.get('services', '–')} | {r.get('endpoints', '–')} | {_v(r, 'nodes', lim)} | "
                     f"{_v(r, 'edges', lim)} | {_v(r, 'findings', lim)} | {_v(r, 'attack_paths', lim)} | "
                     f"{_v(o, 'attack_path_query_ms', lim)} | {_v(r, 'attack_path_query_ms', lim)} | "
                     f"{_v(o, 'mitigation_plan_ms', lim)} | {_v(r, 'mitigation_plan_ms', lim)} | "
                     f"{_v(o, 'phase3_ms', lim)} | {_v(r, 'phase3_ms', lim)} | {p4} | {_v(r, 'peak_rss_mb', lim)} | "
                     f"{_v(r, 'dashboard_kb', lim)} |")
    lines += ["", "## Table 22. Stress test: call-chain density (Phases 3-4 on PostgreSQL)", "",
              f"k = {DENSITY_K} copies (31 services, 111 endpoints) plus d random endpoint-to-endpoint calls per backend "
              "endpoint, across copies. Attack paths follow CALLS chains up to 9 hops, so their number grows quickly with d.", "",
              "| Calls per endpoint d | CALLS edges | Attack paths " + head + " Peak memory 1.3 (MB) |",
              "|" + "---|" * 10]
    for r in new["density"]:
        o = prev.get((r["k"], r["d"]))
        lines.append(f"| {r['d']:g} | {_v(r, 'calls_edges', lim)} | {_v(r, 'attack_paths', lim)} | "
                     f"{_v(o, 'attack_path_query_ms', lim)} | {_v(r, 'attack_path_query_ms', lim)} | "
                     f"{_v(o, 'mitigation_plan_ms', lim)} | {_v(r, 'mitigation_plan_ms', lim)} | "
                     f"{_v(o, 'phase3_ms', lim)} | {_v(r, 'phase3_ms', lim)} | {_v(r, 'peak_rss_mb', lim)} |")
    lines += ["", f"Machine: {new.get('cpus', '?')} CPU cores, Python {new.get('python', '?')}, PostgreSQL 16 in Docker on the same host, "
              "its data folder in memory (tmpfs, 4 GB). 'Out of temp space': the recursive attack path query needed more than the "
              "4 GB of temporary space PostgreSQL had, because the number of paths up to 9 hops grows exponentially with d."]
    (OUT / "tables.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    _figure(new, old)


def _figure(new: dict, old: dict | None) -> None:
    try:
        import matplotlib
    except ImportError:
        return
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 150})
    lim_ms = new["time_limit_s"] * 1000
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.3))
    for ax, exp, xkey, xlabel, title in ((axes[0], "size", "services", "Services", "System size"),
                                         (axes[1], "density", "d", f"Random calls per endpoint ({DENSITY_K} copies, 31 services)",
                                          "Call-chain density")):
        for res, color, label in ((old, "#DD8452", "version 1.2"), (new, "#4C72B0", "version 1.3")):
            if not res:
                continue
            xs, ys, cut = [], [], None
            for r in res[exp]:
                if "skipped" in r:
                    continue
                x = r.get(xkey, r.get("d")) if xkey == "d" else r.get("services")
                if x is None:
                    continue
                if "timeout_s" in r or "error" in r:
                    cut = x if cut is None else cut
                    continue
                xs.append(x)
                ys.append(r["phase3_ms"])
            ax.plot(xs, ys, marker="o", ms=3, color=color, label=f"Phase 3, {label}")
            if cut is not None:
                ax.plot([xs[-1], cut], [ys[-1], lim_ms], color=color, ls=":", lw=1)
                ax.plot([cut], [lim_ms], marker="x", ms=6, color=color)
        ax.axhline(lim_ms, color="#999999", lw=0.8, ls="--")
        ax.text(0.02, 0.97, f"dashed: {new['time_limit_s']} s limit;  x: stopped or failed", transform=ax.transAxes,
                fontsize=7, color="#666666", va="top")
        ax.set_yscale("log")
        ax.set_ylim(top=lim_ms * 5)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Phase 3 time (ms, log scale)")
        ax.set_title(title)
        ax.legend(frameon=False, fontsize=7, loc="lower right")
    fig.tight_layout()
    figs = ROOT / "results" / "figures"
    figs.mkdir(parents=True, exist_ok=True)
    fig.savefig(figs / "fig_stress.png")
    plt.close(fig)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(*sys.argv[2:6])
        return 0
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", default="results/grid/shoplite-C1-s1/raw", help="Phase 1 output of the ShopLite scan to clone")
    ap.add_argument("--pg", default=os.environ.get("ATG_GRAPH_STORE", ""), help="PostgreSQL URL (default: SQLite in a temp file)")
    ap.add_argument("--limit", type=int, default=TIME_LIMIT, help="seconds per configuration")
    ap.add_argument("--version", choices=["1.3", "1.2"], default="1.3", help="1.2 = old fix planner, no ANALYZE")
    ap.add_argument("--report", action="store_true", help="only rebuild the tables from results/stress/stress-*.json")
    a = ap.parse_args()
    if not a.report:
        url = a.pg or f"sqlite:///{tempfile.mkdtemp()}/stress.db"
        run_all(ROOT / a.raw, url, a.limit, a.version)
    report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
