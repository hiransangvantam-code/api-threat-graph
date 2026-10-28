"""
Phase 1 orchestrator:  python -m extractor --config extractor.yaml

Runs the four extractors from the architecture diagram, writes one JSON file
per source into output/raw/ plus a manifest, and (optionally) the HTML report.

    MITPROXY         -> runtime_traffic.json
    OPENAPI          -> openapi.json
    K8S MANIFESTS    -> infrastructure.json
    OPENTELEMETRY    -> callchain.json
                        manifest.json   (what ran, counts, timings, file hashes)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import uuid
from pathlib import Path

import yaml

from . import callchain_discovery, infra_discovery, openapi_discovery, runtime_traffic
from .common import EXTRACTOR_VERSION, SCHEMA, now_iso, write_json

EXTRACTORS = {
    "runtime_traffic": runtime_traffic,
    "openapi": openapi_discovery,
    "infrastructure": infra_discovery,
    "callchain": callchain_discovery,
}


def run(config_path, only: list[str] | None = None, report: bool = True) -> dict:
    """config_path: path to extractor.yaml, or an already-loaded config dict."""
    cfg = config_path if isinstance(config_path, dict) else yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    target = cfg.get("target", {})
    service_map = {str(k): v for k, v in (target.get("service_map") or {}).items()}
    out_dir = Path(cfg.get("output_dir", "output/raw"))
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]

    manifest = {
        "schema": SCHEMA, "extractor_version": EXTRACTOR_VERSION, "run_id": run_id,
        "target": target.get("name"), "started_at": now_iso(), "sources": {},
    }
    t_all = time.perf_counter()
    for name, mod in EXTRACTORS.items():
        scfg = (cfg.get("sources") or {}).get(name) or {}
        if (only and name not in only) or not scfg.get("enabled", True):
            manifest["sources"][name] = {"status": "skipped"}
            continue
        try:
            result = mod.extract(scfg, service_map, run_id)
            path = out_dir / f"{name}.json"
            write_json(path, result)
            blob = path.read_bytes()
            manifest["sources"][name] = {
                "status": "ok", "file": str(path), "sha256": hashlib.sha256(blob).hexdigest(),
                "records": len(result["records"]), "stats": result["stats"],
                "warnings": result["warnings"], "duration_ms": result["duration_ms"],
            }
            print(f"  [ok]   {name:<16} {len(result['records']):>4} records  "
                  f"{result['duration_ms']:>8.1f} ms  -> {path}")
            for w in result["warnings"]:
                print(f"         ! {w}")
        except Exception as exc:  # one broken source should not kill the run
            manifest["sources"][name] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
            print(f"  [fail] {name:<16} {type(exc).__name__}: {exc}")

    manifest["finished_at"] = now_iso()
    manifest["total_duration_ms"] = round((time.perf_counter() - t_all) * 1000, 1)
    write_json(out_dir / "manifest.json", manifest)

    if report:
        from .report import build_report
        rpath = Path(cfg.get("report_path", out_dir.parent / "report.html"))
        build_report(out_dir, rpath)
        print(f"  report -> {rpath}")
    return manifest


def main():
    ap = argparse.ArgumentParser(description="API Threat Graph - Phase 1 extractor")
    ap.add_argument("--config", default="extractor.yaml")
    ap.add_argument("--only", help="comma list: runtime_traffic,openapi,infrastructure,callchain")
    ap.add_argument("--no-report", action="store_true")
    a = ap.parse_args()
    print("Phase 1 - Extractor")
    m = run(a.config, a.only.split(",") if a.only else None, not a.no_report)
    bad = [k for k, v in m["sources"].items() if v["status"] == "error"]
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
