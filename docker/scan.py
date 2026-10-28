"""
One scan of the target system: Phases 1-4 on what the ATG platform captured since
the previous scan.

    docker compose exec atg python docker/scan.py --label vulnerable --manifests k8s

  Phase 1  runtime traffic   the new lines the mitmproxy sidecar wrote   (/data/capture)
           traces            the new span batches the OTel Collector wrote (/data/telemetry)
           OpenAPI           probed live from the target's services over customer-net
           infrastructure    the company's manifests, mounted read-only   (/target/<manifests>)
  Phase 2  EUJF records      output/eujf.json and PostgreSQL table atg_eujf
  Phase 3  threat graph      PostgreSQL tables atg_nodes, atg_edges, atg_findings, atg_paths
  Phase 4  pages             output/site (http://localhost:8080)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pages import (CAPTURE, OUT, ROOT, SITE, TARGET_CFG, TELEMETRY, build_results, capture_files,  # noqa: E402
                   health_checks, load_state, save_state, slug, status_page)

os.chdir(ROOT)
TARGET = Path(os.environ.get("ATG_TARGET_DIR", "/target"))


def wait_until_quiet(max_wait: float = 30) -> None:
    """Spans reach the Collector in batches and are flushed to disk about a second later,
    so wait until neither the sidecar nor the Collector has written anything for 3 s."""
    time.sleep(2)
    last, stable, deadline = None, 0, time.time() + max_wait
    while time.time() < deadline and stable < 3:
        sizes = {str(f): f.stat().st_size for f in capture_files()}
        stable = stable + 1 if sizes == last else 0
        last = sizes
        time.sleep(1)


def take_new(src: Path, dst: Path, st: dict) -> int:
    """Copy what was appended to src/*.jsonl since the last scan (whole lines only)."""
    dst.mkdir(parents=True, exist_ok=True)
    lines = 0
    for f in sorted(src.glob("*.jsonl")):
        off = st["offsets"].get(str(f), 0)
        with f.open("rb") as fh:
            fh.seek(off)
            chunk = fh.read()
        cut = chunk.rfind(b"\n") + 1  # a line still being written stays for the next scan
        if cut:
            (dst / f.name).write_bytes(chunk[:cut])
            lines += chunk[:cut].count(b"\n")
        st["offsets"][str(f)] = off + cut
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", default="scan", help="name of this scan in the trend chart, e.g. vulnerable")
    ap.add_argument("--manifests", default="k8s", help="folder under /target with the deployed manifests")
    a = ap.parse_args()

    st = load_state()
    if st.get("store"):
        os.environ["ATG_GRAPH_STORE"] = st["store"]
    else:
        os.environ.pop("ATG_GRAPH_STORE", None)
    st["scanning"] = a.label
    save_state(st)
    status_page(health_checks(st), scanning=a.label)
    try:
        print(f"[scan] {a.label}: waiting until the sidecar and the Collector are quiet", flush=True)
        wait_until_quiet()
        n = len([p for p in (OUT / "runs").glob("*") if p.is_dir()]) + 1 if (OUT / "runs").exists() else 1
        scan_dir = OUT / "scan-input" / slug(n, a.label)
        shutil.rmtree(scan_dir, ignore_errors=True)
        flows = take_new(CAPTURE, scan_dir / "capture", st)
        batches = take_new(TELEMETRY, scan_dir / "telemetry", st)
        print(f"[scan] new since the last scan: {flows} HTTP flows from the sidecar, {batches} span batches from the Collector",
              flush=True)
        if not flows:
            print("[scan] warning: no traffic captured. Did the customers (users) run go through atg-proxy?", flush=True)

        import yaml
        cfg = yaml.safe_load(TARGET_CFG.read_text(encoding="utf-8"))
        src = cfg["sources"]
        src["runtime_traffic"]["capture_files"] = [str(scan_dir / "capture")]
        src["callchain"]["trace_paths"] = [str(scan_dir / "telemetry")]
        src["infrastructure"]["manifest_paths"] = [str(TARGET / a.manifests)]
        for f in src["openapi"].get("spec_files", []):
            f["path"] = str(TARGET / f["path"])

        from atg.pipeline import run
        result = run(cfg, extract=True, label=a.label)
        run_dir = OUT / "runs" / result["analysis"]["run_id"]
        (run_dir / "scan.json").write_text(json.dumps({
            "label": a.label, "manifests": a.manifests, "flows": flows, "span_batches": batches,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S")}, indent=1), encoding="utf-8")
        SITE.mkdir(parents=True, exist_ok=True)
        shutil.copy(OUT / "report.html", SITE / f"phase1-report-{slug(n, a.label)}.html")
        st["scanning"] = None
        save_state(st)
        build_results(st.get("store"), st.get("started", time.time()))
        s = result["analysis"]["summary"]
        print(f"[scan] {a.label}: {result['eujf']['summary']['endpoints']} APIs, {s['findings']} findings, "
              f"{s['attack_paths']} attack paths, path risk {s['total_path_risk']:g}", flush=True)
        return 0
    except Exception as exc:
        tb = traceback.format_exc()
        print(tb, flush=True)
        st["scanning"] = None
        save_state(st)
        status_page(health_checks(st), failed=f"{a.label}: {exc}", log_tail=tb[-4000:])
        return 1


if __name__ == "__main__":
    sys.exit(main())
