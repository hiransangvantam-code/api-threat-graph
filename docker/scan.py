"""
One scan of the target system: Phases 1-4 on what the ATG platform captured since
the previous scan.

    docker compose exec atg python docker/scan.py --label vulnerable --manifests k8s

  Phase 1  runtime traffic   the new lines the mitmproxy sidecar wrote   (/data/capture, in memory)
           traces            the new span batches the OTel Collector wrote (/data/telemetry, in memory)
           OpenAPI           probed live from the target's services over customer-net
           infrastructure    the company's manifests, mounted read-only   (/target/<manifests>)
  Phase 2  EUJF records      PostgreSQL table atg_eujf (in memory)
  Phase 3  threat graph      PostgreSQL tables atg_nodes, atg_edges, atg_findings, atg_paths (in memory)
  Phase 4  pages             output/site (http://localhost:8080) and the exports in output/site/exports/<scan>/

What happens to the data:
  - the captured traffic and spans this scan read are cleared from the sidecar's and the
    Collector's in-memory files once the scan has them (if nothing new arrived meanwhile;
    otherwise the next scan or STOP clears them)
  - the scan's own copy of that input is deleted as soon as Phase 1 has read it
  - Phase 1 JSON, EUJF JSON and analysis JSON stay in memory (/work) for the /live/ pages
  - only the report pages and the threat graph exports are written to disk
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
from pages import (CAPTURE, LIVE, OUT, ROOT, SITE, TARGET_CFG, TELEMETRY, WORK, build_results,  # noqa: E402
                   capture_files, health_checks, load_state, save_state, slug, status_page)

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


def take_and_clear(src: Path, dst: Path, st: dict, clear: bool = True) -> dict:
    """Copy what was appended to src/*.jsonl since the last scan (whole lines only), then
    empty the source file if nothing was written after what we read. Both writers append
    with O_APPEND, so after the file is emptied their next line starts at byte 0."""
    dst.mkdir(parents=True, exist_ok=True)
    out = {"lines": 0, "bytes": 0, "cleared": 0, "left": 0}
    for f in sorted(src.glob("*.jsonl")):
        size = f.stat().st_size
        off = st["offsets"].get(str(f), 0)
        if off > size:  # the file was emptied or recreated since
            off = 0
        with f.open("rb") as fh:
            fh.seek(off)
            chunk = fh.read()
        cut = chunk.rfind(b"\n") + 1  # a line still being written stays for the next scan
        if cut:
            (dst / f.name).write_bytes(chunk[:cut].replace(b"\x00", b""))
            out["lines"] += chunk[:cut].count(b"\n")
            out["bytes"] += cut
        end = off + cut
        if clear and f.stat().st_size == end:
            with f.open("r+b") as fh:
                fh.truncate(0)
            out["cleared"] += end
            st["offsets"][str(f)] = 0
        else:
            st["offsets"][str(f)] = end
            out["left"] += f.stat().st_size   # new data arrived meanwhile: cleared by the next scan or STOP
    return out


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
    scan_dir = None
    try:
        print(f"[scan] {a.label}: waiting until the sidecar and the Collector are quiet", flush=True)
        wait_until_quiet()
        runs = WORK / "runs"
        n = len([p for p in runs.glob("*") if p.is_dir()]) + 1 if runs.exists() else 1
        s = slug(n, a.label)
        scan_dir = WORK / "scan-input" / s
        shutil.rmtree(scan_dir, ignore_errors=True)
        cap = take_and_clear(CAPTURE, scan_dir / "capture", st)
        tel = take_and_clear(TELEMETRY, scan_dir / "telemetry", st)
        save_state(st)
        print(f"[scan] new since the last scan: {cap['lines']} HTTP flows from the sidecar, {tel['lines']} span batches "
              f"from the Collector ({(cap['cleared'] + tel['cleared']) / 1024:.0f} KB cleared from their memory)", flush=True)
        if not cap["lines"]:
            print("[scan] warning: no traffic captured. Did the customers (users) run go through atg-proxy?", flush=True)

        import yaml
        cfg = yaml.safe_load(TARGET_CFG.read_text(encoding="utf-8"))
        src = cfg["sources"]
        src["runtime_traffic"]["capture_files"] = [str(scan_dir / "capture")]
        src["callchain"]["trace_paths"] = [str(scan_dir / "telemetry")]
        src["infrastructure"]["manifest_paths"] = [str(TARGET / a.manifests)]
        for f in src["openapi"].get("spec_files", []):
            f["path"] = str(TARGET / f["path"])
        cfg["output_dir"] = str(WORK / "raw")             # Phase 1 JSON: memory only
        cfg["report_path"] = str(WORK / "report.html")

        from atg.pipeline import run
        result = run(cfg, extract=True, label=a.label)
        shutil.rmtree(scan_dir, ignore_errors=True)       # the copy of the captured input is no longer needed
        scan_dir = None
        analysis, eujf = result["analysis"], result["eujf"]
        run_dir = runs / analysis["run_id"]

        # Phase 1 output and the Phase 1 report: viewable under /live/ while the review runs
        live = LIVE / "scans" / s
        shutil.rmtree(live, ignore_errors=True)
        (live / "raw").mkdir(parents=True, exist_ok=True)
        for f in (WORK / "raw").glob("*.json"):
            shutil.move(str(f), live / "raw" / f.name)
        shutil.move(str(WORK / "report.html"), LIVE / f"phase1-report-{s}.html")
        for name in ("raw", "eujf.json", "analysis.json", "dashboard.html"):  # duplicates of run_dir
            p = WORK / name
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)

        from atg.export import export_all
        exports = export_all(analysis, eujf, SITE / "exports" / s)
        (run_dir / "scan.json").write_text(json.dumps({
            "label": a.label, "manifests": a.manifests, "flows": cap["lines"], "span_batches": tel["lines"],
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "data": {"read_bytes": cap["bytes"] + tel["bytes"], "cleared_bytes": cap["cleared"] + tel["cleared"],
                     "left_in_buffers_bytes": cap["left"] + tel["left"], "input_copy_deleted": True,
                     "exports": {k: str(p.relative_to(SITE)) for k, p in exports.items()}},
        }, indent=1), encoding="utf-8")
        st["scanning"] = None
        save_state(st)
        build_results(st.get("store"), st.get("started", time.time()))
        sm = analysis["summary"]
        print(f"[scan] {a.label}: {eujf['summary']['endpoints']} APIs, {sm['findings']} findings, "
              f"{sm['attack_paths']} attack paths, path risk {sm['total_path_risk']:g}", flush=True)
        print(f"[scan] threat graph exported to output/site/exports/{s}/ (GraphML, JSON, SARIF, SVG)", flush=True)
        return 0
    except Exception as exc:
        tb = traceback.format_exc()
        print(tb, flush=True)
        if scan_dir is not None:
            shutil.rmtree(scan_dir, ignore_errors=True)
        st["scanning"] = None
        save_state(st)
        status_page(health_checks(st), failed=f"{a.label}: {exc}", log_tail=tb[-4000:])
        return 1


if __name__ == "__main__":
    sys.exit(main())
