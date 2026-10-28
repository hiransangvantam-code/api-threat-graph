"""
Run one pipeline stage in a fresh process and record wall time and peak RSS.

  python bench/timed.py extract   CONFIG.yaml  OUT.json
  python bench/timed.py normalize RAW_DIR      OUT.json   (all sources, reconciliation on)
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    stage, arg, out = sys.argv[1:4]
    t0 = time.perf_counter()
    if stage == "extract":
        import contextlib
        import io
        import yaml
        from extractor.run import run
        with contextlib.redirect_stdout(io.StringIO()):
            m = run(yaml.safe_load(Path(arg).read_text(encoding="utf-8")), report=False)
        detail = {k: v.get("duration_ms") for k, v in m["sources"].items()}
        status = {k: v["status"] for k, v in m["sources"].items()}
    elif stage == "normalize":
        from atg.normalizer import normalize
        e = normalize(Path(arg))
        detail = {"endpoints": len(e["endpoints"]), "dependencies": len(e["dependencies"])}
        status = {}
    else:
        raise SystemExit(f"unknown stage {stage}")
    wall = (time.perf_counter() - t0) * 1000
    # VmHWM is this process's own high-water mark. ru_maxrss is not: on Linux it
    # carries over the parent's RSS from fork/exec, which inflates small numbers.
    try:
        hwm = next(l for l in Path("/proc/self/status").read_text().splitlines() if l.startswith("VmHWM:"))
        rss_kb = int(hwm.split()[1])
    except (OSError, StopIteration):
        try:  # macOS reports bytes, others KiB; Windows has no resource module
            import resource
            rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            rss_kb = rss_kb / 1024 if sys.platform == "darwin" else rss_kb
        except ImportError:
            rss_kb = 0
    Path(out).write_text(json.dumps({"stage": stage, "wall_ms": round(wall, 1), "peak_rss_mb": round(rss_kb / 1024, 1),
                                     "detail": detail, "status": status}, indent=1))


if __name__ == "__main__":
    main()
