"""
Phase 1 only: run the four extractors against the ShopLite demo, end to end.

    python scripts/run_extractor.py

1. starts the 4 ShopLite services (FastAPI + OpenTelemetry)
2. starts mitmproxy with two listeners
      :8080  reverse proxy in front of the gateway   (north-south traffic)
      :8081  forward proxy the services call through (east-west traffic)
3. sends realistic user traffic through :8080
4. runs the four extractors  ->  output/raw/*.json (+ manifest.json) and output/report.html
5. shuts everything down

output/raw/ is the hand-off to Phase 2. Its format: docs/RAW_DATA_CONTRACT.md
Works on Windows, macOS and Linux. Needs: pip install -r requirements.txt
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
import yaml

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


def wait_for(url: str, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    with httpx.Client(trust_env=False, timeout=1, headers={"User-Agent": "atg-extractor/demo-healthcheck"}) as c:
        while time.time() < deadline:
            try:
                c.get(url)
                return
            except httpx.HTTPError:
                time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {url}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=25, help="traffic generator rounds")
    ap.add_argument("--hardened", action="store_true", help="use the hardened Kubernetes manifests")
    a = ap.parse_args()
    k8s = "demo_target/k8s-hardened" if a.hardened else "demo_target/k8s"
    for d in ("output/capture", "output/telemetry", "output/raw"):
        shutil.rmtree(d, ignore_errors=True)
        Path(d).mkdir(parents=True, exist_ok=True)
    logs = Path("output/logs")
    logs.mkdir(parents=True, exist_ok=True)
    env = {**os.environ,
           "SERVICE_HOSTS": "user-service=127.0.0.1:8001,order-service=127.0.0.1:8002,payment-service=127.0.0.1:8003",
           "TELEMETRY_DIR": str(ROOT / "output/telemetry"),
           "MESH_PROXY": f"http://127.0.0.1:{MITM_MESH}",
           "GATEWAY_CONFIG": str(ROOT / k8s / "gateway.yaml"),
           "SHOPLITE_HARDENED": "1" if a.hardened else "0"}
    procs: list[subprocess.Popen] = []
    try:
        print("[1/4] starting ShopLite services")
        for mod, port in SERVICES:
            procs.append(subprocess.Popen(
                [sys.executable, "-m", "uvicorn", f"{mod}:app", "--app-dir", "demo_target/services",
                 "--port", str(port), "--log-level", "warning"],
                env=env, stdout=open(logs / f"{mod}.log", "w"), stderr=subprocess.STDOUT))
        print("[2/4] starting mitmproxy (reverse :8080, mesh :8081)")
        procs.append(subprocess.Popen(
            [find_mitmdump(), "-q", "-s", "extractor/mitm_addon.py",
             "--mode", f"reverse:http://127.0.0.1:8000@{MITM_REVERSE}", "--mode", f"regular@{MITM_MESH}",
             "--set", "atg_capture=output/capture/flows.jsonl"],
            stdout=open(logs / "mitmproxy.log", "w"), stderr=subprocess.STDOUT))
        for _, port in SERVICES:
            wait_for(f"http://127.0.0.1:{port}/health")
        wait_for(f"http://127.0.0.1:{MITM_REVERSE}/health")

        print("[3/4] generating traffic")
        subprocess.run([sys.executable, "demo_target/traffic_generator.py", "--rounds", str(a.rounds)], check=True)
        time.sleep(1.0)  # let the last spans and flows reach disk

        print("[4/4] running the extractor (the services stay up: OpenAPI is probed live)")
        cfg = yaml.safe_load(Path("extractor.yaml").read_text(encoding="utf-8"))
        cfg["sources"]["infrastructure"]["manifest_paths"] = [k8s]
        from extractor.run import run
        run(cfg)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    print("\ndone.\n  output/raw/*.json    hand-off to Phase 2 (docs/RAW_DATA_CONTRACT.md)\n"
          "  output/report.html   Phase 1 report, open it in a browser")
    return 0


if __name__ == "__main__":
    sys.exit(main())
