"""
Re-run only the infrastructure extractor on stored runs, after a fix to how
deployment or gateway config is parsed. Manifests and gateway configs do not
change between runs, so nothing needs to be running. Also rescores Phase 1.

    python bench/refresh_infra.py results/grid results/hardened
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench.evaluate import evaluate_run  # noqa: E402
from extractor import infra_discovery  # noqa: E402
from extractor.common import write_json  # noqa: E402


def refresh(run_dir: Path, rescore: bool) -> None:
    cfg = yaml.safe_load((run_dir / "extractor.yaml").read_text(encoding="utf-8"))
    sm = {str(k): v for k, v in cfg["target"]["service_map"].items()}
    man_p = run_dir / "raw" / "manifest.json"
    man = json.loads(man_p.read_text())
    res = infra_discovery.extract(cfg["sources"]["infrastructure"], sm, man["run_id"])
    path = run_dir / "raw" / "infrastructure.json"
    write_json(path, res)
    ent = man["sources"].get("infrastructure", {})
    ent.update({"status": "ok", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "records": len(res["records"])})
    man["sources"]["infrastructure"] = ent
    man_p.write_text(json.dumps(man, indent=2))
    if rescore and (run_dir / "run.json").exists():
        info = json.loads((run_dir / "run.json").read_text())
        if "metrics" in info:
            info["metrics"] = evaluate_run(info["testbed"], run_dir)
            (run_dir / "run.json").write_text(json.dumps(info, indent=1))


def main():
    for root in sys.argv[1:]:
        for d in sorted(Path(root).iterdir()):
            if (d / "extractor.yaml").exists() and (d / "raw").exists():
                refresh(d, rescore=True)
                print("refreshed", d.name, flush=True)


if __name__ == "__main__":
    main()
