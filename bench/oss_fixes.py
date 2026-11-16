"""
Measured risk reduction on the ten open-source systems (Section V-C of the report).

1. Take ATG's base scan of each system (bench/oss_eval.py --tag base) and the fixes its plan
   recommends that are changes to the deployment files, not to the code:
     netpol     a NetworkPolicy for the workload: ATG's own YAML from the hardening report,
                written unchanged into the system's manifest folder (Kubernetes only; Docker Compose
                has no network policy object)
     clusterip  a NodePort / LoadBalancer Service becomes ClusterIP; in Docker Compose, the
                service's published ports are removed
     harden     the container runs as a non-root user, cannot escalate privileges, has resource
                limits, and its image is pinned to a fixed version (tag 1.0.0 stands in for the
                system's real release tag)
2. Apply them to a copy of the system's real deployment files: results/opensource/fixes/<id>/
   (the original upstream/ is not touched).
3. Predict the attack-path risk left after exactly these fixes, with the planner's own model
   (atg/analysis.py: a fix removes its findings' paths, netpol also the in-cluster actor's first
   hop and clusterip the internet's).
4. bench/oss_eval.py --tag fixed --config-root results/opensource/fixes rescans with the fixed
   files and the same users; this script's --report compares measured with predicted.

    python bench/oss_fixes.py apply
    python bench/oss_eval.py --tag fixed --config-root results/opensource/fixes --no-zap --no-overhead
    python bench/oss_fixes.py report
"""
from __future__ import annotations

import argparse
import glob
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "opensource"))
from fetch import SYSTEMS  # noqa: E402
from atg.analysis import EDGE_CUT, assign_actions  # noqa: E402
from atg.hardening import stack_fix  # noqa: E402

EVAL = ROOT / "results" / "opensource" / "eval"
FIXES = ROOT / "results" / "opensource" / "fixes"
CONFIG_KINDS = ("netpol", "clusterip", "harden")
WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod", "Job", "CronJob", "DeploymentConfig"}


def base_scan(sid: str, tag: str = "base") -> tuple[dict, dict]:
    """The scan's analysis; the version 1.6 recomputation (bench/oss_rescore.py) when there is one."""
    v16 = EVAL / tag / sid / "v16" / "analysis.json"
    run = str(v16) if v16.exists() else sorted(glob.glob(str(EVAL / tag / sid / "runs" / "*" / "analysis.json")))[-1]
    a = json.loads(Path(run).read_text(encoding="utf-8"))
    e = json.loads(Path(run.replace("analysis.json", "eujf.json")).read_text(encoding="utf-8"))
    return a, e


def predicted_left(analysis: dict, chosen: set[str]) -> float:
    """Total attack-path risk after the chosen actions, as the planner computes it."""
    findings, paths = analysis["findings"], analysis["attack_paths"]
    actions = assign_actions([dict(f) for f in findings])
    of_finding = defaultdict(list)
    for i, p in enumerate(paths):
        of_finding[p["finding_id"]].append(i)
    by_entry = defaultdict(list)
    for i, p in enumerate(paths):
        if len(p["nodes"]) > 1:
            by_entry[(p["nodes"][0], p["nodes"][1])].append(i)
    killed = set()
    for a in actions:
        if a["id"] not in chosen:
            continue
        killed |= {i for fid in a["finding_ids"] for i in of_finding.get(fid, [])}
        actor = EDGE_CUT.get(a["kind"])
        if actor:
            killed |= set(by_entry.get((actor, a["target"]), []))
    left = 0.0
    for fid, idx in of_finding.items():
        left += max((paths[i]["apcr"] for i in idx if i not in killed), default=0)
    return round(left, 2)


# ---------------------------------------------------------------- editing the deployment files
def load_docs(path: Path) -> list | None:
    try:
        return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception:
        return None


def save_docs(path: Path, docs: list) -> None:
    path.write_text(yaml.safe_dump_all([d for d in docs], sort_keys=False), encoding="utf-8")


def pod_spec(doc: dict) -> dict | None:
    spec = doc.get("spec") or {}
    if doc.get("kind") == "Pod":
        return spec
    if doc.get("kind") == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return ((spec.get("template") or {}).get("spec"))


def pin(image: str) -> str:
    last = image.rsplit("/", 1)[-1]
    if "@" in image:
        return image
    if ":" in last:
        repo, tag = image.rsplit(":", 1)
        return f"{repo}:1.0.0" if tag in ("latest", "") else image
    return image + ":1.0.0"


def harden_container(c: dict) -> None:
    sc = c.setdefault("securityContext", {}) or {}
    c["securityContext"] = sc
    sc.update({"runAsNonRoot": True, "runAsUser": 10001, "allowPrivilegeEscalation": False, "privileged": False})
    res = c.setdefault("resources", {}) or {}
    c["resources"] = res
    res.setdefault("limits", {"cpu": "500m", "memory": "512Mi"})
    if c.get("image"):
        c["image"] = pin(str(c["image"]))


def apply_k8s(cfg_dir: Path, manifest_paths: list[str], actions: list[dict], eujf: dict, findings: list[dict]) -> list[str]:
    log = []
    files = []
    for mp in manifest_paths:
        p = cfg_dir / mp
        files += [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.suffix in (".yaml", ".yml"))
    want = defaultdict(set)
    for a in actions:
        want[a["kind"]].add(a["target"].split(":", 1)[1])
    services_by_name = {s["name"]: s for s in eujf.get("services", [])}
    # ATG names a service after its Kubernetes Service; the container settings live in the workload
    workload_of = {n: (s.get("workload") or n) for n, s in services_by_name.items()}
    labels_of = {n: s.get("pod_labels") or {} for n, s in services_by_name.items()}
    want["harden_wl"] = {workload_of.get(n, n) for n in want["harden"]}
    for f in files:
        docs = load_docs(f)
        if docs is None:
            continue
        changed = False
        for d in docs:
            if not isinstance(d, dict):
                continue
            name = (d.get("metadata") or {}).get("name")
            kind = d.get("kind")
            tl = ((d.get("metadata") or {}).get("labels") if kind == "Pod" else
                  ((((d.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels"))) or {}
            by_labels = any(labels_of.get(t) and all(tl.get(k) == v for k, v in labels_of[t].items()) for t in want["harden"])
            if kind in WORKLOADS and (by_labels or name in want["harden_wl"] or name in want["harden"]):
                ps = pod_spec(d) or {}
                for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
                    harden_container(c)
                changed = True
                log.append(f"harden {name} ({f.relative_to(cfg_dir)})")
            if kind == "Service" and (d.get("spec") or {}).get("type") in ("NodePort", "LoadBalancer"):
                sel = (d.get("spec") or {}).get("selector") or {}
                if name in want["clusterip"] or any(sel and all(labels_of.get(t, {}).get(k) == v for k, v in sel.items())
                                                    for t in want["clusterip"]):
                    d["spec"]["type"] = "ClusterIP"
                    for port in d["spec"].get("ports") or []:
                        port.pop("nodePort", None)
                    changed = True
                    log.append(f"clusterip {name} ({f.relative_to(cfg_dir)})")
        if changed:
            save_docs(f, docs)
    # NetworkPolicies: ATG's YAML from the hardening report, unchanged, one file
    pols = []
    for f in findings:
        if f["rule_id"] == "API8-NETPOL" and f["target"].split(":", 1)[1] in want["netpol"]:
            _, snippet = stack_fix(f, eujf)
            pols.append(snippet)
            log.append(f"netpol {f['target'].split(':', 1)[1]}")
    if pols:
        first = cfg_dir / manifest_paths[0]
        if first.is_dir():
            (first / "atg-fix-networkpolicies.yaml").write_text("\n---\n".join(pols) + "\n", encoding="utf-8")
        else:   # the system lists files, not folders (Bookinfo): add the policies to its first file
            with first.open("a", encoding="utf-8") as fh:
                fh.write("\n---\n" + "\n---\n".join(pols) + "\n")
    return log


def apply_compose(cfg_dir: Path, compose_files: list[str], actions: list[dict]) -> list[str]:
    log = []
    want = defaultdict(set)
    for a in actions:
        want[a["kind"]].add(a["target"].split(":", 1)[1])
    for cf in compose_files:
        p = cfg_dir / cf
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        for name, sv in (doc.get("services") or {}).items():
            sv = sv or {}
            if name in want["clusterip"] and sv.get("ports"):
                sv.pop("ports")
                log.append(f"unpublish {name} ({cf})")
            if name in want["harden"]:
                sv["user"] = "10001"
                sv["mem_limit"] = "512m"
                if sv.get("image") and "$" not in str(sv["image"]):
                    sv["image"] = pin(str(sv["image"]))
                log.append(f"harden {name} ({cf})")
            doc["services"][name] = sv
        p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return log


def apply(sid: str) -> dict:
    a, _ = base_scan(sid)
    # the EUJF again from the scan's Phase 1 files, with this version's normalizer (it records each
    # workload's pod labels, which the NetworkPolicy fix needs); findings and paths come from the scan
    from atg.normalizer import normalize
    e = normalize(Path(glob.glob(str(EVAL / "base" / sid / "live" / "scans" / "*" / "raw"))[-1]))
    src = ROOT / "opensource" / sid
    dst = FIXES / sid
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git"))
    tcfg = yaml.safe_load((dst / "atg-target.yaml").read_text(encoding="utf-8"))
    infra = tcfg["sources"]["infrastructure"]
    actions = [x for x in assign_actions([dict(f) for f in a["findings"]]) if x["kind"] in CONFIG_KINDS]
    if infra.get("compose_files"):
        actions = [x for x in actions if x["kind"] != "netpol"]      # no network policy object in Compose
        log = apply_compose(dst, infra["compose_files"], actions)
    else:
        log = apply_k8s(dst, infra.get("manifest_paths") or [], actions, e, a["findings"])
    chosen = {x["id"] for x in actions}
    plan = a["mitigation_plan"]
    out = {"system": sid, "R_before": plan["total_path_risk"], "findings_before": len(a["findings"]),
           "applied": sorted(chosen), "applied_by_kind": {k: sum(1 for x in actions if x["kind"] == k) for k in CONFIG_KINDS},
           "R_predicted": predicted_left(a, chosen), "edits": log}
    (FIXES / f"{sid}.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"{sid:18} {len(chosen):3} config fixes {out['applied_by_kind']}  R {out['R_before']} -> predicted {out['R_predicted']}")
    return out


def report() -> None:
    rows = []
    for sid in SYSTEMS:
        pf = FIXES / f"{sid}.json"
        mf = EVAL / "fixed" / f"{sid}.json"
        if not (pf.exists() and mf.exists()):
            continue
        p = json.loads(pf.read_text())
        m, _ = base_scan(sid, "fixed")
        rows.append({**p, "R_measured": m["summary"]["total_path_risk"], "findings_after": m["summary"]["findings"],
                     "paths_after": m["summary"]["attack_paths"]})
    (FIXES / "summary.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    for r in rows:
        print(f"{r['system']:18} R {r['R_before']:7} -> predicted {r['R_predicted']:7} measured {r['R_measured']:7} "
              f"({100 * (1 - r['R_measured'] / r['R_before']):.1f}% removed)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=["apply", "report"])
    ap.add_argument("systems", nargs="*", default=SYSTEMS)
    a = ap.parse_args()
    if a.what == "apply":
        FIXES.mkdir(parents=True, exist_ok=True)
        for sid in a.systems:
            apply(sid)
    else:
        report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
