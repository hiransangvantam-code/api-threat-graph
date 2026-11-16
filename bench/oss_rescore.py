"""
Phases 2-3 again, with this version of ATG, on the Phase 1 output kept from the evaluation scans
(results/opensource/eval/<tag>/<id>/live/scans/*/raw). No system is started: the Phase 1 files are
what the scan read from the running system, so this gives the analysis the current code would
have produced on the same scan.

Used after version 1.6 changed how the internet reaches published services (atg/analysis.py),
which changes attack paths, risk and fix plans but not inventory or findings.

    python bench/oss_rescore.py            base and fixed scans of all ten systems

Writes <id>/v16/eujf.json and <id>/v16/analysis.json next to each scan, and prints R before/after.
"""
from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "opensource"))
from atg.analysis import analyze  # noqa: E402
from atg.graphstore import GraphStore  # noqa: E402
from atg.normalizer import normalize  # noqa: E402
from fetch import SYSTEMS  # noqa: E402

EVAL = ROOT / "results" / "opensource" / "eval"


def rescore(tag: str, sid: str) -> dict:
    raw = Path(sorted(glob.glob(str(EVAL / tag / sid / "live" / "scans" / "*" / "raw")))[-1])
    eujf = normalize(raw)
    store = GraphStore(None)
    a = analyze(eujf, store)
    store.close()
    out = EVAL / tag / sid / "v16"
    out.mkdir(parents=True, exist_ok=True)
    (out / "eujf.json").write_text(json.dumps(eujf), encoding="utf-8")
    (out / "analysis.json").write_text(json.dumps(a), encoding="utf-8")
    return a


def main() -> int:
    for tag in ("base", "fixed"):
        for sid in SYSTEMS:
            if not (EVAL / tag / sid).exists():
                continue
            old = json.loads(Path(sorted(glob.glob(str(EVAL / tag / sid / "runs" / "*" / "analysis.json")))[-1]).read_text())
            a = rescore(tag, sid)
            print(f"{tag:6} {sid:18} findings {old['summary']['findings']:4} -> {a['summary']['findings']:4}  "
                  f"paths {old['summary']['attack_paths']:4} -> {a['summary']['attack_paths']:4}  "
                  f"R {old['summary']['total_path_risk']:7} -> {a['summary']['total_path_risk']:7}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
