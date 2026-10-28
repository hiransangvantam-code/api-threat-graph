"""
Experiment runner for Section IV (Phase 1 extractor evaluation).

One run = start a testbed, put mitmproxy in front of it, drive a workload, run the
four extractors, then score every combination of sources against ground truth.

  python bench/run_experiment.py grid        [--testbeds a,b] [--seeds 1-5]      main results (C1/C2)
  python bench/run_experiment.py overhead    [--testbed trainticket] [--reps 3]  mitmproxy latency cost
  python bench/run_experiment.py scale       [--testbed trainticket]             runtime vs volume
  python bench/run_experiment.py curve       [--testbed trainticket]             coverage vs #requests
  python bench/run_experiment.py hardened    [--seeds 1-5]                        ShopLite after the fixes
  python bench/run_experiment.py one TESTBED CONDITION SEED                      a single run

Conditions
  C1 ideal      north-south AND east-west capture (every service calls through the
                mesh listener), every service emits traces
  C2 realistic  north-south capture only (gateway ingress), about 30% of services
                emit no traces (chosen per seed)

Everything lands in results/<experiment>/<run>/ ; results/README.md says how to read it.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import time
import uuid
import zlib
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench.common import TESTBEDS, load_topology  # noqa: E402
from bench.evaluate import evaluate_run  # noqa: E402

PY = sys.executable
RESULTS = ROOT / "results"
REQUESTS = {"trainticket": 3000, "crapi": 1500}
SHOPLITE_ROUNDS = 40
SHOPLITE = [("gateway", "api-gateway", 8000), ("user_service", "user-service", 8001),
            ("order_service", "order-service", 8002), ("payment_service", "payment-service", 8003)]


def mitmdump() -> str:
    exe = shutil.which("mitmdump") or str(Path(PY).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump"))
    if not Path(exe).exists():
        sys.exit("mitmdump not found (pip install mitmproxy)")
    return exe


def wait_for(url: str, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    with httpx.Client(trust_env=False, timeout=1, headers={"User-Agent": "atg-extractor/bench-healthcheck"}) as c:
        while time.time() < deadline:
            try:
                c.get(url)
                return
            except httpx.HTTPError:
                time.sleep(0.3)
    raise RuntimeError(f"timed out waiting for {url}")


def stop(procs):
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()


def untraced_set(names: list[str], seed: int, testbed: str, share: float = 0.3) -> list[str]:
    rnd = random.Random(zlib.crc32(f"{testbed}:{seed}".encode()))
    return sorted(rnd.sample(names, max(1, round(share * len(names)))))


# ------------------------------------------------------------------ extractor config
def extractor_config(testbed: str, run_dir: Path, ports: dict, hardened: bool = False) -> dict:
    topo = load_topology(testbed)
    tb = TESTBEDS / testbed
    service_map = {f"127.0.0.1:{p}": n for n, p in ports.items()}
    srcs = {
        "runtime_traffic": {"enabled": True, "capture_files": [str(run_dir / "capture")]},
        "openapi": {"enabled": True, "timeout_s": 2},
        "infrastructure": {"enabled": True},
        "callchain": {"enabled": True, "trace_paths": [str(run_dir / "telemetry")]},
    }
    if testbed == "shoplite":
        srcs["openapi"]["spec_files"] = [{"path": str(ROOT / "demo_target/specs/payment-service.v1.yaml"),
                                          "service": "payment-service"}]
        srcs["infrastructure"]["manifest_paths"] = [str(ROOT / ("demo_target/k8s-hardened" if hardened else "demo_target/k8s"))]
    else:
        srcs["infrastructure"]["manifest_paths"] = [str(tb / "k8s")]
        gw = topo["gateway"]
        if gw["kind"] == "spring-cloud-gateway":
            srcs["infrastructure"]["gateway_configs"] = [
                {"path": str(tb / gw["config"]), "type": "spring-cloud-gateway", "service": gw["service"]}]
        elif gw["kind"] == "nginx":
            srcs["infrastructure"]["gateway_configs"] = [
                {"path": str(tb / gw["config"]), "type": "nginx", "service": gw["service"],
                 "env_from": [str(p) for p in sorted((tb / "k8s").glob("web-*.yaml"))], "env": {"HTTP_PROTOCOL": "http"}}]
        if topo.get("documentation") == "spec-file":
            # the published spec covers the whole API at the gateway; split it per backend
            # with the same prefixes the nginx config routes on
            srcs["openapi"]["spec_files"] = [{"path": str(tb / topo["spec_file"]),
                                              "service_by_prefix": {r["path"]: r["service"] for r in gw["routes"]}}]
    return {"target": {"name": topo["name"], "service_map": service_map}, "sources": srcs,
            "output_dir": str(run_dir / "raw"), "report_path": str(run_dir / "report.html")}


# ------------------------------------------------------------------ one run
def run_once(testbed: str, condition: str, seed: int, run_dir: Path, *, requests: int | None = None,
             coverage: float = 0.8, floor: bool = True, capture: str = "auto", evaluate: bool = True,
             hardened: bool = False, score: bool = True) -> dict:
    """capture: auto (follow condition) | none (workload hits gateway directly) | ns | ns+ew.
    hardened: ShopLite with the recommended fixes applied (SHOPLITE_HARDENED=1, k8s-hardened).
    score: compute the Phase 1 metrics (needs the testbed's ground truth, so off for hardened)."""
    if run_dir.exists():
        shutil.rmtree(run_dir)
    for d in ("capture", "telemetry", "gt", "raw", "logs"):
        (run_dir / d).mkdir(parents=True)
    if capture == "auto":
        capture = "ns+ew" if condition == "C1" else "ns"
    logs = run_dir / "logs"
    procs: list[subprocess.Popen] = []
    replica = testbed != "shoplite"
    base, rev, mesh_port = (9200, 9180, 9181) if replica else (8000, 8080, 8081)
    mesh_url = f"http://127.0.0.1:{mesh_port}" if capture == "ns+ew" else ""
    info = {"testbed": testbed, "condition": condition, "seed": seed, "capture": capture, "hardened": hardened}
    try:
        if replica:
            topo = load_topology(testbed)
            names = [topo["gateway"]["service"]] + [s["name"] for s in topo["services"]]
            untraced = untraced_set(names, seed, testbed) if condition == "C2" else []
            cmd = [PY, str(ROOT / "bench/replica.py"), "--testbed", testbed, "--base-port", str(base),
                   "--run-dir", str(run_dir), "--untraced", ",".join(untraced)]
            if mesh_url:
                cmd += ["--mesh-proxy", mesh_url]
            procs.append(subprocess.Popen(cmd, stdout=open(logs / "replica.log", "w"), stderr=subprocess.STDOUT))
            ready = f"http://127.0.0.1:{base}/__replica/ready"
        else:
            names = [n for _, n, _ in SHOPLITE]
            untraced = untraced_set(names, seed, testbed) if condition == "C2" else []
            env = {**os.environ,
                   "SERVICE_HOSTS": "user-service=127.0.0.1:8001,order-service=127.0.0.1:8002,payment-service=127.0.0.1:8003",
                   "TELEMETRY_DIR": str(run_dir / "telemetry"), "MESH_PROXY": mesh_url,
                   "GATEWAY_CONFIG": str(ROOT / ("demo_target/k8s-hardened" if hardened else "demo_target/k8s") / "gateway.yaml"),
                   "SHOPLITE_HARDENED": "1" if hardened else "0",
                   "ATG_UNTRACED": ",".join(untraced), "ATG_GT_LOG": str(run_dir / "gt")}
            for mod, _, port in SHOPLITE:
                procs.append(subprocess.Popen(
                    [PY, "-m", "uvicorn", f"{mod}:app", "--app-dir", str(ROOT / "demo_target/services"),
                     "--port", str(port), "--log-level", "warning"],
                    env=env, stdout=open(logs / f"{mod}.log", "w"), stderr=subprocess.STDOUT))
            ready = f"http://127.0.0.1:{base}/health"
        info["untraced"] = untraced
        if capture != "none":
            modes = ["--mode", f"reverse:http://127.0.0.1:{base}@{rev}"]
            if capture == "ns+ew":
                modes += ["--mode", f"regular@{mesh_port}"]
            procs.append(subprocess.Popen(
                [mitmdump(), "-q", "-s", str(ROOT / "extractor/mitm_addon.py"), *modes,
                 "--set", f"atg_capture={run_dir / 'capture/flows.jsonl'}"],
                stdout=open(logs / "mitmproxy.log", "w"), stderr=subprocess.STDOUT))
        wait_for(ready)
        entry = f"http://127.0.0.1:{rev if capture != 'none' else base}"
        if capture != "none":
            wait_for(entry + ("/__replica/ready" if replica else "/health"))
        ports = json.loads((run_dir / "ports.json").read_text()) if replica else {n: p for _, n, p in SHOPLITE}
        if not replica:
            (run_dir / "ports.json").write_text(json.dumps(ports, indent=1))

        # ---- workload
        t0 = time.perf_counter()
        if replica:
            cmd = [PY, str(ROOT / "bench/workload.py"), "--testbed", testbed, "--gateway", entry,
                   "--ports", str(run_dir / "ports.json"), "--requests", str(requests or REQUESTS[testbed]),
                   "--coverage", str(coverage), "--seed", str(seed), "--out", str(run_dir / "workload.json")]
            if mesh_url:
                cmd += ["--mesh-proxy", mesh_url]
            if not floor:
                cmd.append("--no-floor")
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        else:
            subprocess.run([PY, str(ROOT / "demo_target/traffic_generator.py"), "--gateway", entry,
                            "--mesh-proxy", mesh_url or "", "--rounds", str(requests or SHOPLITE_ROUNDS),
                            "--seed", str(seed)], check=True, stdout=open(logs / "traffic.log", "w"))
            (run_dir / "workload.json").write_text(json.dumps({"rounds": requests or SHOPLITE_ROUNDS,
                                                               "wall_s": round(time.perf_counter() - t0, 2)}))
        time.sleep(1.0)  # last spans and flows reach disk

        # ---- Phase 1 (while the testbed is still up: OpenAPI is probed live)
        cfg = extractor_config(testbed, run_dir, ports, hardened=hardened)
        (run_dir / "extractor.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
        if evaluate:
            subprocess.run([PY, str(ROOT / "bench/timed.py"), "extract", str(run_dir / "extractor.yaml"),
                            str(run_dir / "perf_extract.json")], check=True)
    finally:
        stop(procs)
    info["workload"] = json.loads((run_dir / "workload.json").read_text())
    if not evaluate:
        (run_dir / "run.json").write_text(json.dumps(info, indent=1))
        return info
    subprocess.run([PY, str(ROOT / "bench/timed.py"), "normalize", str(run_dir / "raw"),
                    str(run_dir / "perf_normalize.json")], check=True)
    info["perf"] = {"extract": json.loads((run_dir / "perf_extract.json").read_text()),
                    "normalize": json.loads((run_dir / "perf_normalize.json").read_text())}
    if score:
        info["metrics"] = evaluate_run(testbed, run_dir)
    (run_dir / "run.json").write_text(json.dumps(info, indent=1))
    # keep results small: telemetry and capture stay, logs of passing runs go
    shutil.rmtree(logs, ignore_errors=True)
    return info


def _seeds(s: str) -> list[int]:
    if "-" in s:
        a, b = s.split("-")
        return list(range(int(a), int(b) + 1))
    return [int(x) for x in s.split(",")]


# ------------------------------------------------------------------ experiments
def grid(a):
    out = RESULTS / "grid"
    for tb in a.testbeds.split(","):
        for cond in ("C1", "C2"):
            for seed in _seeds(a.seeds):
                d = out / f"{tb}-{cond}-s{seed}"
                if (d / "run.json").exists() and not a.force:
                    continue
                t0 = time.time()
                r = run_once(tb, cond, seed, d)
                m = r["metrics"]["subsets"]["OTKC"]
                print(f"{tb:<12} {cond} s{seed}  recall={m['M1']['recall_all']:.3f} prec={m['M1']['precision']:.3f} "
                      f"edgesR={m['M4']['recall_all']}  ({time.time() - t0:.0f}s)", flush=True)


def overhead(a):
    """Same workload three ways: straight to the gateway, through the reverse proxy,
    and through reverse proxy + mesh listener for every east-west call."""
    out = RESULTS / "overhead"
    rows = []
    for rep in range(1, a.reps + 1):
        for cap in ("none", "ns", "ns+ew"):
            d = out / f"{a.testbed}-{cap.replace('+', '_')}-r{rep}"
            r = run_once(a.testbed, "C1", 100 + rep, d, capture=cap, evaluate=False)
            w = r["workload"]
            rows.append({"testbed": a.testbed, "capture": cap, "rep": rep, **w["latency_ms"],
                         "wall_s": w.get("wall_s"), "requests": w.get("requests")})
            print(f"{a.testbed} {cap:<6} rep{rep}  p50={w['latency_ms']['p50']} p95={w['latency_ms']['p95']} "
                  f"wall={w['wall_s']}s", flush=True)
            shutil.rmtree(d / "telemetry", ignore_errors=True)
    (out / f"{a.testbed}-overhead.json").write_text(json.dumps(rows, indent=1))


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_NUM = re.compile(r"(?<=/)\d{2,}(?=/|$)")
_TRACE = re.compile(r'"traceId": "([0-9a-fA-F]{32})"')


def _fresh_ids(path: str, rnd: random.Random) -> str:
    path = _UUID.sub(lambda m: str(uuid.UUID(int=rnd.getrandbits(128), version=4)), path)
    return _NUM.sub(lambda m: str(rnd.randint(10, 99999)), path)


def scale(a):
    """Take one C1 capture and multiply it (x1, x5, x10, x20) with fresh IDs in every
    copy, then time Phase 1 and Phase 2 on each size."""
    out = RESULTS / "scale"
    base = out / f"{a.testbed}-base"
    if not (base / "run.json").exists():
        run_once(a.testbed, "C1", 1, base, evaluate=False)
    flows = (base / "capture/flows.jsonl").read_text().splitlines()
    spans = {f.name: f.read_text().splitlines() for f in (base / "telemetry").glob("*.jsonl")}
    rows = []
    for k in (1, 5, 10, 20):
        d = out / f"{a.testbed}-x{k}"
        if d.exists():
            shutil.rmtree(d)
        (d / "capture").mkdir(parents=True)
        (d / "telemetry").mkdir()
        rnd = random.Random(k)
        with (d / "capture/flows.jsonl").open("w") as fh:
            for i in range(k):
                for line in flows:
                    f = json.loads(line)
                    if i:
                        f["path"] = _fresh_ids(f["path"], rnd)
                        if "url" in f:
                            f["url"] = _fresh_ids(f["url"], rnd)
                    fh.write(json.dumps(f) + "\n")
        for name, lines in spans.items():
            with (d / "telemetry" / name).open("w") as fh:
                for i in range(k):  # every copy is a new set of traces: rewrite the trace id prefix
                    for line in lines:
                        fh.write((_TRACE.sub(lambda m: f'"traceId": "{i:04x}{m.group(1)[4:]}"', line) if i else line) + "\n")
        cfg = extractor_config(a.testbed, d, json.loads((base / "ports.json").read_text()))
        cfg["sources"]["openapi"]["enabled"] = False  # nothing is running; spec probing is not volume-dependent
        (d / "extractor.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
        subprocess.run([PY, str(ROOT / "bench/timed.py"), "extract", str(d / "extractor.yaml"),
                        str(d / "perf_extract.json")], check=True)
        subprocess.run([PY, str(ROOT / "bench/timed.py"), "normalize", str(d / "raw"),
                        str(d / "perf_normalize.json")], check=True)
        pe = json.loads((d / "perf_extract.json").read_text())
        pn = json.loads((d / "perf_normalize.json").read_text())
        n_spans = sum(len(v) for v in spans.values()) * k
        rows.append({"factor": k, "flows": len(flows) * k, "span_lines": n_spans,
                     "extract_ms": pe["wall_ms"], "extract_rss_mb": pe["peak_rss_mb"],
                     "traffic_ms": pe["detail"]["runtime_traffic"], "traces_ms": pe["detail"]["callchain"],
                     "infra_ms": pe["detail"]["infrastructure"],
                     "normalize_ms": pn["wall_ms"], "normalize_rss_mb": pn["peak_rss_mb"],
                     "inventory": pn["detail"]["endpoints"]})
        print(json.dumps(rows[-1]), flush=True)
        shutil.rmtree(d / "capture")
        shutil.rmtree(d / "telemetry")
    (out / f"{a.testbed}-scale.json").write_text(json.dumps(rows, indent=1))


def curve(a):
    """Recall as the workload grows, with no per-endpoint minimum (pure Zipf)."""
    out = RESULTS / "curve"
    rows = []
    for n in (100, 250, 500, 1000, 2000, 4000, 8000):
        for seed in _seeds(a.seeds):
            d = out / f"{a.testbed}-n{n}-s{seed}"
            r = run_once(a.testbed, "C1", seed, d, requests=n, coverage=1.0, floor=False)
            s = r["metrics"]["subsets"]
            rows.append({"requests": n, "seed": seed, **{k: s[k]["M1"]["recall_all"] for k in ("T", "C", "TC", "OTKC")},
                         "edges_T_C": s["TC"]["M4"]["recall_all"], "edges_all": s["OTKC"]["M4"]["recall_all"]})
            print(json.dumps(rows[-1]), flush=True)
            for sub in ("capture", "telemetry", "gt"):
                shutil.rmtree(d / sub, ignore_errors=True)
    (out / f"{a.testbed}-curve.json").write_text(json.dumps(rows, indent=1))


def hardened(a):
    """ShopLite with the fixes the dashboard recommends, same seeds and conditions as the
    grid, so Phase 3 can compare before / after (risk reduction actually achieved)."""
    out = RESULTS / "hardened"
    for cond in ("C1", "C2"):
        for seed in _seeds(a.seeds):
            d = out / f"shoplite-{cond}-s{seed}"
            if (d / "run.json").exists() and not a.force:
                continue
            run_once("shoplite", cond, seed, d, hardened=True, score=False)
            print(f"shoplite hardened {cond} s{seed}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grid")
    g.add_argument("--testbeds", default="shoplite,trainticket,crapi")
    g.add_argument("--seeds", default="1-5")
    g.add_argument("--force", action="store_true")
    o = sub.add_parser("overhead")
    o.add_argument("--testbed", default="trainticket")
    o.add_argument("--reps", type=int, default=3)
    s = sub.add_parser("scale")
    s.add_argument("--testbed", default="trainticket")
    c = sub.add_parser("curve")
    c.add_argument("--testbed", default="trainticket")
    c.add_argument("--seeds", default="1-3")
    h = sub.add_parser("hardened")
    h.add_argument("--seeds", default="1-5")
    h.add_argument("--force", action="store_true")
    one = sub.add_parser("one")
    one.add_argument("testbed")
    one.add_argument("condition", choices=["C1", "C2"])
    one.add_argument("seed", type=int)
    a = ap.parse_args()
    if a.cmd == "one":
        r = run_once(a.testbed, a.condition, a.seed, RESULTS / "one" / f"{a.testbed}-{a.condition}-s{a.seed}")
        print(json.dumps({k: r["metrics"]["subsets"][k] for k in ("T", "OTKC")}, indent=1))
    else:
        {"grid": grid, "overhead": overhead, "scale": scale, "curve": curve, "hardened": hardened}[a.cmd](a)


if __name__ == "__main__":
    main()
