"""
Workload for a replica testbed: client sessions through the gateway, plus a few
in-cluster jobs that call internal endpoints directly.

  --coverage     fraction of public endpoints the workload ever touches. Real
                 workloads never exercise everything; the rest stays unobserved.
  --anon-rate    share of requests sent without an Authorization header
  --job-rate     share of internal-only endpoints (not routed, not called by any
                 other service) that some in-cluster job calls
Request popularity follows a Zipf-like curve, and every exercised endpoint gets
at least two requests. Latency of every request is written to --out.

usage: python bench/workload.py --testbed trainticket --gateway http://127.0.0.1:8180
                                --ports RUN/ports.json --requests 1500 --seed 1 --out RUN/workload.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import statistics
import time
from pathlib import Path

import httpx

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.common import fill, load_topology, public_path  # noqa: E402

UA = "Mozilla/5.0 (bench-workload)"


def plan(topo: dict, rnd: random.Random, n: int, coverage: float, anon_rate: float, job_rate: float,
         floor: bool = True):
    called = {(c["service"], c["method"], c["path"]) for s in topo["services"] for e in s["endpoints"] for c in e["calls"]}
    public, internal = [], []
    for s in topo["services"]:
        for e in s["endpoints"]:
            pp = public_path(topo, e["path"], s["name"])
            if pp:
                public.append((s["name"], e, pp))
            elif (s["name"], e["method"], e["path"]) not in called:
                internal.append((s["name"], e))
    rnd.shuffle(public)
    k = max(1, math.ceil(coverage * len(public)))
    chosen = public[:k]
    weights = [1 / (i + 1) ** 0.8 for i in range(len(chosen))]
    seq = [c for c in chosen for _ in range(2)] if floor else []
    rest = max(0, n - len(seq))
    seq += rnd.choices(chosen, weights=weights, k=rest)
    rnd.shuffle(seq)
    reqs = [{"kind": "public", "service": s, "method": e["method"], "template": pp,
             "anon": rnd.random() < anon_rate} for s, e, pp in seq]
    jobs = [x for x in internal if rnd.random() < job_rate]
    for s, e in jobs:
        for _ in range(2):
            reqs.append({"kind": "job", "service": s, "method": e["method"], "template": e["path"], "anon": False})
    return reqs, {"public_endpoints": len(public), "exercised_public": len(chosen), "internal_only": len(internal),
                  "jobs": len(jobs)}


async def run(a) -> dict:
    topo = load_topology(a.testbed)
    ports = json.loads(Path(a.ports).read_text())
    rnd = random.Random(a.seed)
    reqs, info = plan(topo, rnd, a.requests, a.coverage, a.anon_rate, a.job_rate, floor=not a.no_floor)
    ids = topo.get("id_style", "uuid")
    lat, status = [], {}
    gw = httpx.AsyncClient(base_url=a.gateway, trust_env=False, timeout=30, limits=httpx.Limits(max_connections=a.concurrency))
    job_client = httpx.AsyncClient(proxy=a.mesh_proxy or None, trust_env=False, timeout=30)
    sem = asyncio.Semaphore(a.concurrency)
    users = [f"Bearer bench-user-{i}" for i in range(20)]

    async def one(r):
        path = fill(r["template"], rnd, ids)
        headers = {"user-agent": UA}
        if not r["anon"]:
            headers["authorization"] = rnd.choice(users)
        body = {"ref": "bench", "n": rnd.randint(1, 9)} if r["method"] in ("POST", "PUT", "PATCH") else None
        async with sem:
            t0 = time.perf_counter()
            try:
                if r["kind"] == "public":
                    resp = await gw.request(r["method"], path, headers=headers, json=body)
                else:
                    resp = await job_client.request(r["method"], f"http://127.0.0.1:{ports[r['service']]}{path}",
                                                    headers={**headers, "user-agent": "report-job/1.0"}, json=body)
                code = resp.status_code
            except httpx.HTTPError:
                code = "error"
            lat.append((time.perf_counter() - t0) * 1000)
            status[str(code)] = status.get(str(code), 0) + 1

    t0 = time.perf_counter()
    await asyncio.gather(*(one(r) for r in reqs))
    wall = time.perf_counter() - t0
    await gw.aclose()
    await job_client.aclose()
    lat.sort()
    out = {**info, "requests": len(reqs), "status": status, "wall_s": round(wall, 2),
           "latency_ms": {"p50": round(statistics.median(lat), 2), "p95": round(lat[int(0.95 * (len(lat) - 1))], 2),
                          "mean": round(statistics.fmean(lat), 2)}}
    Path(a.out).write_text(json.dumps(out, indent=1))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--testbed", required=True)
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--ports", required=True)
    ap.add_argument("--mesh-proxy", default="")
    ap.add_argument("--requests", type=int, default=1500)
    ap.add_argument("--coverage", type=float, default=0.8)
    ap.add_argument("--anon-rate", type=float, default=0.1)
    ap.add_argument("--job-rate", type=float, default=0.3)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-floor", action="store_true",
                    help="pure Zipf sampling, no 2-request minimum per endpoint (coverage-vs-volume curve)")
    ap.add_argument("--out", required=True)
    print(json.dumps(asyncio.run(run(ap.parse_args()))))


if __name__ == "__main__":
    main()
