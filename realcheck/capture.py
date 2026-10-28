"""
Start mitmproxy in front of the real crAPI and record API flows.

    python realcheck/capture.py            # proxy :9888 -> crAPI :8888
    python realcheck/capture.py --fresh    # delete an earlier capture first

Then use crAPI in the browser at http://localhost:9888 (not 8888, or nothing is
recorded). Press Ctrl+C here when you are done.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "realcheck/out/capture"


def find_mitmdump() -> str:
    exe = shutil.which("mitmdump")
    if exe:
        return exe
    cand = Path(sys.executable).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
    if cand.exists():
        return str(cand)
    sys.exit("mitmdump not found. Run: pip install mitmproxy")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8888", help="where crapi-web listens")
    ap.add_argument("--port", type=int, default=9888, help="where the browser should go")
    ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()
    if a.fresh and OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    flows = OUT / "flows.jsonl"
    print(f"Recording to {flows}")
    print(f"Open http://localhost:{a.port} in your browser. Ctrl+C to stop.")
    try:
        subprocess.run([find_mitmdump(), "-q", "-s", str(ROOT / "extractor/mitm_addon.py"),
                        "--mode", f"reverse:{a.target}@{a.port}",
                        "--set", "keep_host_header=true",  # crAPI's nginx rewrites links using Host
                        "--set", f"atg_capture={flows}"])
    except KeyboardInterrupt:
        pass
    n = sum(1 for _ in flows.open(encoding="utf-8")) if flows.exists() else 0
    print(f"\nstopped. {n} flows recorded.")
    if n:
        print("next: python -m extractor --config realcheck/extractor-crapi-real.yaml")


if __name__ == "__main__":
    main()
