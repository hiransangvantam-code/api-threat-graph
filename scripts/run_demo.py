"""
One command to see the whole pipeline (Phases 1-4) end to end, no Docker needed:

    python scripts/run_demo.py                       # ShopLite as shipped (vulnerable)
    python scripts/run_demo.py --scenario hardened   # ShopLite with the recommended fixes
    python scripts/run_demo.py --scenario both       # both, so the trend chart shows before -> after
    python scripts/run_demo.py --extractor-only      # Phase 1 only -> output/raw/*.json + output/report.html

1. starts the 4 ShopLite services (FastAPI + OpenTelemetry)
2. starts mitmproxy with two listeners
      :8080  reverse proxy in front of the gateway   (north-south traffic)
      :8081  forward proxy the services call through (east-west traffic)
3. replays realistic user traffic through :8080
4. runs the four extractors              ->  output/raw/*.json, output/report.html
5. normalizer, rule engine, threat graph  ->  output/eujf.json, output/analysis.json, output/atg.db
6. dashboard                              ->  output/dashboard.html
7. shuts everything down

Works on macOS, Linux and Windows. Needs: pip install -r requirements.txt
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

SERVICES = [("gateway", 8000), ("user_service", 8001), ("order_service", 8002), ("payment_service", 8003)]
MITM_REVERSE, MITM_MESH = 8080, 8081


def find_mitmdump() -> str:
    exe = shutil.which("mitmdump")
    if exe:
        return exe
    cand = Path(sys.executable).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
    if cand.exists():
        return str(cand)
    sys.exit("mitmdump not found. Run: pip install mitmproxy")


def wait_for(url: str, timeout: float = 20) -> None:
    deadline = time.time() + timeout
    with httpx.Client(trust_env=False, timeout=1, headers={"User-Agent": "atg-extractor/demo-healthcheck"}) as c:
        while time.time() < deadline:
            try:
                c.get(url)
                return
            except httpx.HTTPError:
                time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {url}")


def run_scenario(scenario: str, extractor_only: bool = False) -> int:
    hardened = scenario == "hardened"
    k8s = "demo_target/k8s-hardened" if hardened else "demo_target/k8s"
    for d in ("output/capture", "output/telemetry", "output/raw"):
        shutil.rmtree(d, ignore_errors=True)
        Path(d).mkdir(parents=True, exist_ok=True)
    logs = Path("output/logs")
    logs.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "SERVICE_HOSTS": "user-service=127.0.0.1:8001,order-service=127.0.0.1:8002,payment-service=127.0.0.1:8003",
        "TELEMETRY_DIR": str(ROOT / "output/telemetry"),
        "MESH_PROXY": f"http://127.0.0.1:{MITM_MESH}",
        "GATEWAY_CONFIG": str(ROOT / k8s / "gateway.yaml"),
        "SHOPLITE_HARDENED": "1" if hardened else "0",
    }
    procs: list[subprocess.Popen] = []
    try:
        print(f"\n=== ShopLite, scenario: {scenario} ===")
        print("[1/5] starting ShopLite services")
        for mod, port in SERVICES:
            procs.append(subprocess.Popen(
                [sys.executable, "-m", "uvicorn", f"{mod}:app", "--app-dir", "demo_target/services",
                 "--port", str(port), "--log-level", "warning"],
                env=env, stdout=open(logs / f"{mod}.log", "w"), stderr=subprocess.STDOUT))

        print("[2/5] starting mitmproxy (reverse :8080, mesh :8081)")
        procs.append(subprocess.Popen(
            [find_mitmdump(), "-q", "-s", "extractor/mitm_addon.py",
             "--mode", f"reverse:http://127.0.0.1:8000@{MITM_REVERSE}",
             "--mode", f"regular@{MITM_MESH}",
             "--set", "atg_capture=output/capture/flows.jsonl"],
            stdout=open(logs / "mitmproxy.log", "w"), stderr=subprocess.STDOUT))

        for _, port in SERVICES:
            wait_for(f"http://127.0.0.1:{port}/health")
        wait_for(f"http://127.0.0.1:{MITM_REVERSE}/health")

        print("[3/5] generating traffic")
        subprocess.run([sys.executable, "demo_target/traffic_generator.py", "--rounds",
                        os.environ.get("DEMO_ROUNDS", "25")], check=True)
        time.sleep(1.0)  # let the last spans and flows hit disk

        import yaml
        cfg = yaml.safe_load(Path("extractor.yaml").read_text(encoding="utf-8"))
        cfg["sources"]["infrastructure"]["manifest_paths"] = [k8s]
        if extractor_only:
            print("[4/5] running the extractor (Phase 1 only)")
            from extractor.run import run as extract
            extract(cfg)
            print("[5/5] done. Open output/report.html")
            return 0
        print("[4/5] running the pipeline (Phases 1-4)")
        from atg.pipeline import run
        result = run(cfg, extract=True, label=scenario)
        print(f"[5/5] done. Open {result['dashboard']}  (Phase 1 detail: output/report.html)")
        return 0
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=["vulnerable", "hardened", "both"], default="vulnerable")
    ap.add_argument("--extractor-only", action="store_true", help="run Phase 1 only (no analysis, no dashboard)")
    a = ap.parse_args()
    if a.extractor_only:
        return run_scenario("hardened" if a.scenario == "hardened" else "vulnerable", extractor_only=True)
    if a.scenario != "both":
        return run_scenario(a.scenario)
    run_scenario("vulnerable")
    first = sorted(Path("output/runs").iterdir())[-1]
    rc = run_scenario("hardened")
    # the vulnerable run's page, refreshed so its trend chart shows the hardened run too
    from atg.pipeline import rebuild
    rebuild(str(first))
    shutil.copy(first / "dashboard.html", "output/dashboard-vulnerable.html")
    shutil.copy("output/dashboard.html", "output/dashboard-hardened.html")
    print("before: output/dashboard-vulnerable.html\nafter:  output/dashboard-hardened.html")
    return rc


if __name__ == "__main__":
    sys.exit(main())
