"""
Scoring shared by every tool in the open-source benchmark (bench/run_opensource.py for ATG,
bench/run_tools.py for the others).

A finding counts when it names the same weakness category and the same place as a label in
opensource/<id>/ground-truth.json. Places are compared after one normalisation that every tool
gets: a Kubernetes workload name (productpage-v1) and the Service in front of it (productpage)
are the same place, and so are "configmap:x" and a ConfigMap called x. A finding on an
endpoint also counts for a label on the service it belongs to (an unauthenticated
service-to-service call on any endpoint of paymentservice matches "A5 at paymentservice").
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "opensource"))

GROUPS = {"Configuration": ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"],
          "API behaviour": ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10"],
          "Inventory and visibility": ["O1", "O2"]}
CAT_GROUP = {c: g for g, cs in GROUPS.items() for c in cs}
CAT_NAMES = {
    "C1": "may run as root", "C2": "privileged", "C3": "no resource limits", "C4": "mutable image tag",
    "C5": "published outside the gateway", "C6": "no network segmentation", "C7": "secret in deployment files",
    "C8": "public entry without TLS", "C9": "missing container hardening", "C10": "service account token mounted",
    "A1": "no authentication on a sensitive operation", "A2": "broken object level authorization",
    "A3": "admin function exposed", "A4": "debug or diagnostic endpoint exposed",
    "A5": "service-to-service call without credentials", "A6": "login without rate limit",
    "A7": "credential in the URL", "A8": "SSRF-prone input", "A9": "bulk sensitive data", "A10": "third-party API use",
    "O1": "no API document", "O2": "not traced"}

# ATG rule -> category
ATG_CATS = {"TS-01": "A1", "TS-02": "A1", "TS-03": "A1", "TS-04": "C7", "TS-05": "C8", "TS-06": "A7", "TS-07": "A6",
            "TS-08": "A5", "API1": "A2", "API3": "A9", "API4": "C3", "API5": "A3", "API7": "A8", "API8-DEBUG": "A4",
            "API8-PRIV": "C2", "API8-ROOT": "C1", "API8-NODEPORT": "C5", "API8-NETPOL": "C6", "API8-TAG": "C4",
            "API9-SHADOW": "O1", "API9-ZOMBIE": "O1", "API9-NOSPEC": "O1", "API10": "A10",
            "LT-01": "O2", "LT-02": "O2", "LT-03": "O2", "LT-04": None}


def aliases(sid: str) -> dict[str, str]:
    """workload name -> Service name (Kubernetes systems)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("oss_build", ROOT / "opensource" / "build.py")
    ob = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ob)
    from config_labels import k8s_labels
    s = ob.load(sid)
    if not s["artifacts"].get("manifests"):
        return {}
    _, al = k8s_labels(s, ROOT / "opensource" / sid / "upstream")
    # several Services can select one workload (Online Boutique: frontend and frontend-external).
    # Keep the workload's own name if a Service has it, else a Service system.yaml knows, else the first.
    known = set(s["services"])
    out: dict[str, str] = {}
    for w in sorted({w for ws in al.values() for w in ws}):
        cands = sorted(svc for svc, ws in al.items() if w in ws)
        out[w] = w if w in cands else next((c for c in cands if c in known), cands[0])
    return out


def norm(target: str, al: dict) -> str:
    kind, _, rest = target.partition(":")
    if kind == "svc":
        return "svc:" + al.get(rest, rest)
    if kind == "ep":
        svc, _, tail = rest.partition(":")
        return f"ep:{al.get(svc, svc)}:{tail}"
    return target


def svc_of(target: str) -> str | None:
    kind, _, rest = target.partition(":")
    if kind == "svc":
        return target
    if kind == "ep":
        return "svc:" + rest.split(":", 1)[0]
    return None


def score(sid: str, pairs: set[tuple[str, str]], scope: set[str] | None = None) -> dict:
    """pairs: (category, target) the tool reported, targets already normalised.
    scope: categories the tool is able to report at all (for 'in reach' numbers)."""
    gt = json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))
    labels = {(l["cat"], l["target"]) for l in gt["labels"]}
    reported_svc = {(c, svc_of(t)) for c, t in pairs if svc_of(t)}
    found = {lab for lab in labels if lab in pairs or (lab[1].startswith("svc:") and lab in reported_svc)}
    confirmed = {p for p in pairs if p in labels or (p[0], svc_of(p[1])) in labels}
    out = {"labels": len(labels), "found": len(found), "reported": len(pairs), "confirmed": len(confirmed),
           "by_group": {}, "by_cat": {}, "missed": sorted(labels - found), "unconfirmed": sorted(pairs - confirmed)}
    for g, cats in GROUPS.items():
        gl = {l for l in labels if l[0] in cats}
        gp = {p for p in pairs if p[0] in cats}
        gc = {p for p in confirmed if p[0] in cats}
        out["by_group"][g] = {"labels": len(gl), "found": len(gl & found), "reported": len(gp), "confirmed": len(gc)}
    by = defaultdict(lambda: [0, 0])
    for l in labels:
        by[l[0]][0] += 1
        by[l[0]][1] += l in found
    out["by_cat"] = {k: {"labels": v[0], "found": v[1]} for k, v in sorted(by.items())}
    if scope is not None:
        inl = {l for l in labels if l[0] in scope}
        out["in_reach"] = {"labels": len(inl), "found": len(inl & found)}
    return out


def endpoint_score(sid: str, listed: set[str], al: dict) -> dict:
    gt = json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))
    real = {norm(e["id"], al) for e in gt["endpoints"]}
    listed = {norm(x, al) for x in listed}
    return {"real": len(real), "listed": len(listed), "correct": len(real & listed),
            "missed": sorted(real - listed), "extra": sorted(listed - real)}
