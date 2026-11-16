"""
Stress test built from a real system (Section V-D): the EUJF of ATG's scan of Online Boutique
(results/opensource/eval/base/online-boutique, 12 workloads, 25 operations) is cloned k times into
one cluster. Copy c renames every service x to x-c, so each copy keeps the real records and the
rules fire the way they do on Online Boutique. Two experiments, as in bench/stress.py:

  size     k = 1 ... 30 copies (12 -> 360 workloads)
  density  k = 5 copies plus d random operation-to-operation calls per operation across copies;
           attack paths follow call chains up to 9 hops, so their number grows with d

Each configuration runs in a fresh process against PostgreSQL with a time limit (bench/stress.py
does the measuring).

    docker run -d --name atg-stress-pg -e POSTGRES_USER=atg -e POSTGRES_PASSWORD=atg -e POSTGRES_DB=atg -p 55432:5432 \\
        --tmpfs /var/lib/postgresql/data:size=4g postgres:16-alpine
    python bench/oss_stress.py --pg postgresql://atg:atg@localhost:55432/atg
"""
from __future__ import annotations

import argparse
import copy
import glob
import json
import os
import platform
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))
import stress  # noqa: E402

OUT = ROOT / "results" / "opensource" / "eval" / "stress.json"
SIZES = [1, 2, 5, 10, 20, 30, 50, 100]
DENSITY_K = 5
DENSITIES = [0, 0.5, 1, 1.5, 2, 2.5, 3, 4]


def clone(base: dict, k: int, density: float = 0.0, seed: int = 1) -> dict:
    names = sorted({s["name"] for s in base["services"]}, key=len, reverse=True)
    rx = re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, names)) + r")(?![\w-])")
    out = copy.deepcopy(base)
    out["run_id"] = f"stress-{base.get('target', 'system')}-k{k}-d{density:g}"
    lists = [key for key, v in base.items() if isinstance(v, list)]
    for key in lists:
        out[key] = []
    text = json.dumps(base)
    for c in range(1, k + 1):
        cl = json.loads(rx.sub(lambda m: f"{m.group(1)}-{c}", text))
        for key in lists:
            out[key] += cl[key]
        if c == 1:
            out["gateway"] = cl.get("gateway")
    if density:
        rnd = random.Random(seed)
        eps = out["endpoints"]
        deps = {}
        for _ in range(int(round(density * len(eps)))):
            a, b = rnd.sample(eps, 2)
            if a["service"] == b["service"]:
                continue
            out.setdefault("call_chains", []).append({"traces": 1, "hops": [
                {"depth": 0, "service": a["service"], "operation": f"{a['method']} {a['path']}"},
                {"depth": 1, "service": b["service"], "operation": f"{b['method']} {b['path']}"}]})
            d = deps.setdefault((a["service"], b["service"]), {"from": a["service"], "to": b["service"], "calls": 0,
                                                                 "operations": [], "evidence": "trace"})
            d["calls"] += 1
        out["dependencies"] += list(deps.values())
    for i, e in enumerate(out["endpoints"], 1):
        e["api_id"] = f"API-{i:04d}"
    out["summary"] = {**base["summary"], "endpoints": len(out["endpoints"]), "services": len(out["services"])}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pg", required=True)
    ap.add_argument("--system", default="online-boutique")
    ap.add_argument("--limit", type=int, default=300)
    a = ap.parse_args()
    v16 = ROOT / "results" / "opensource" / "eval" / "base" / a.system / "v16" / "eujf.json"
    run = str(v16) if v16.exists() else sorted(glob.glob(str(ROOT / "results" / "opensource" / "eval" / "base" / a.system / "runs" / "*" / "eujf.json")))[-1]
    base = json.loads(Path(run).read_text(encoding="utf-8"))
    res = {"base": str(Path(run).relative_to(ROOT)), "system": a.system, "time_limit_s": a.limit, "cpus": os.cpu_count(),
           "python": platform.python_version(), "size": [], "density": []}
    for name, configs in (("size", [(k, 0) for k in SIZES]), ("density", [(DENSITY_K, d) for d in DENSITIES])):
        stop = False
        for k, d in configs:
            if stop:
                res[name].append({"k": k, "d": d, "skipped": "a smaller configuration hit the limit"})
                continue
            r = {"k": k, "d": d, **stress.measure(clone(base, k, d), a.pg, a.limit, "1.3")}
            print(name, json.dumps(r), flush=True)
            res[name].append(r)
            stop = "timeout_s" in r or "error" in r
            OUT.write_text(json.dumps(res, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
