"""
Other tools on the ten open-source systems, scored with the same ground truth as ATG
(bench/oss_scoring.py).

    python bench/run_tools.py                     every static tool on every system
    python bench/run_tools.py --tools checkov,kubescape bookinfo

Static tools read the systems' real files in opensource/<id>/upstream/:
  Kubernetes / IaC   Checkov 3 (Palo Alto Prisma Cloud's open-source scanner), Kubescape 3 (ARMO, CNCF),
                     kube-linter (Red Hat StackRox), Polaris (Fairwinds)
  API documents      Spectral with the OWASP API ruleset (Stoplight), Checkov's OpenAPI checks
  Source code        Bandit (Python only), gosec (Go only), njsscan (Node.js only)
Each finding is mapped to a weakness category (the tables below) and a place, and timed.
The dynamic tools (OWASP ZAP, Schemathesis) need a running system and an API document:
bench/run_dynamic.py.

Tool locations: set TOOLS_DIR (default /var/tmp/tools: bin/, venv/, node_modules/).
Writes results/opensource/tools/<tool>/<id>.json and results/opensource/tools/scores.json.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
import oss_scoring as sc  # noqa: E402
from fetch import SYSTEMS  # noqa: E402

T = Path(os.environ.get("TOOLS_DIR", "/var/tmp/tools"))
OUT = ROOT / "results" / "opensource" / "tools"

# ---------------------------------------------------------------- finding -> category
CHECKOV = {"CKV_K8S_23": "C1", "CKV_K8S_6": "C1", "CKV_K8S_16": "C2", "CKV_K8S_2": "C2", "CKV_K8S_11": "C3",
           "CKV_K8S_13": "C3", "CKV_K8S_14": "C4", "CKV2_K8S_6": "C6", "CKV_K8S_22": "C9", "CKV_K8S_20": "C9",
           "CKV_K8S_28": "C9", "CKV_K8S_37": "C9", "CKV_K8S_38": "C10"}
KUBESCAPE = {"C-0013": "C1", "C-0057": "C2", "C-0004": "C3", "C-0009": "C3", "C-0050": "C3", "C-0270": "C3",
             "C-0271": "C3", "C-0075": "C4", "C-0260": "C6", "C-0030": "C6", "C-0012": "C7", "C-0017": "C9",
             "C-0016": "C9", "C-0046": "C9", "C-0055": "C9", "C-0034": "C10", "C-0190": "C10", "C-0256": "C5",
             "C-0263": "C8"}
KUBELINTER = {"run-as-non-root": "C1", "privileged-container": "C2", "unset-cpu-requirements": "C3",
              "unset-memory-requirements": "C3", "latest-tag": "C4", "non-isolated-pod": "C6", "env-var-secret": "C7",
              "no-read-only-root-fs": "C9", "privilege-escalation-container": "C9", "drop-net-raw-capability": "C9"}
POLARIS = {"runAsRootAllowed": "C1", "runAsPrivileged": "C2", "cpuLimitsMissing": "C3", "memoryLimitsMissing": "C3",
           "tagNotSpecified": "C4", "missingNetworkPolicy": "C6", "notReadOnlyRootFilesystem": "C9",
           "privilegeEscalationAllowed": "C9", "insecureCapabilities": "C9", "dangerousCapabilities": "C9",
           "automountServiceAccountToken": "C10"}
# what each tool can report at all (for "in reach" recall)
SCOPE = {"checkov": set(CHECKOV.values()) | {"C7"}, "kubescape": set(KUBESCAPE.values()),
         "kube-linter": set(KUBELINTER.values()), "polaris": set(POLARIS.values()),
         "spectral": {"A1", "A6", "C8"}, "bandit": {"C7"}, "gosec": {"C7"}, "njsscan": {"C7"}}

# service source folders, for the code scanners and the language-coverage table
SOURCES = {
    "online-boutique": {n: f"src/{n}" for n in ["frontend", "cartservice", "productcatalogservice", "currencyservice",
                                                "recommendationservice", "shippingservice", "paymentservice", "emailservice",
                                                "checkoutservice", "adservice"]},
    "bank-of-anthos": {"frontend": "src/frontend", "userservice": "src/accounts/userservice", "contacts": "src/accounts/contacts",
                       "balancereader": "src/ledger/balancereader", "transactionhistory": "src/ledger/transactionhistory",
                       "ledgerwriter": "src/ledger/ledgerwriter"},
    "robot-shop": {n: n for n in ["web", "catalogue", "user", "cart", "shipping", "payment", "ratings", "dispatch"]},
    "acme-air": {"acmeair-main-service": "mainservice", "acmeair-auth-service": "authservice",
                 "acmeair-booking-service": "bookingservice", "acmeair-customer-service": "customerservice",
                 "acmeair-flight-service": "flightservice"},
    "petclinic": {"api-gateway": "spring-petclinic-api-gateway", "customers-service": "spring-petclinic-customers-service",
                  "visits-service": "spring-petclinic-visits-service", "vets-service": "spring-petclinic-vets-service",
                  "genai-service": "spring-petclinic-genai-service", "admin-server": "spring-petclinic-admin-server",
                  "config-server": "spring-petclinic-config-server"},
    "piggymetrics": {n: n for n in ["gateway", "auth-service", "account-service", "statistics-service", "notification-service",
                                    "monitoring"]},
    "lakeside-mutual": {n: n for n in ["customer-core", "customer-self-service-backend", "customer-management-backend",
                                       "policy-management-backend", "spring-boot-admin"]},
    "ftgo": {n: n for n in ["ftgo-api-gateway", "ftgo-consumer-service", "ftgo-order-service", "ftgo-order-history-service",
                            "ftgo-kitchen-service", "ftgo-restaurant-service"]},
    "hotel-reservation": {n: f"hotelReservation/services/{n}" for n in ["frontend", "search", "geo", "rate", "profile",
                                                                        "recommendation", "user", "reservation"]},
    "bookinfo": {n: f"samples/bookinfo/src/{n}" for n in ["productpage", "details", "reviews", "ratings"]},
}
LANG_TOOL = {"bandit": "Python", "gosec": "Go", "njsscan": "Node.js"}
# services with source code but no HTTP API in system.yaml (so no language there)
OTHER_LANG = {"robot-shop": {"dispatch": "Go", "web": "nginx"}}


def system(sid: str) -> dict:
    return yaml.safe_load((ROOT / "opensource" / sid / "system.yaml").read_text(encoding="utf-8"))


def up(sid: str) -> Path:
    return ROOT / "opensource" / sid / "upstream"


def manifest_files(sid: str) -> list[Path]:
    files = []
    for p in system(sid).get("artifacts", {}).get("manifests", []):
        q = up(sid) / p
        files += sorted(q.rglob("*.y*ml")) if q.is_dir() else [q]
    return files


def spec_files(sid: str) -> list[tuple[str, Path]]:
    s = system(sid)
    out = [(f["service"], up(sid) / f["path"]) for f in s.get("artifacts", {}).get("spec_files", [])]
    for name in (s.get("spec") or {}).get("services", []):
        out.append((name, ROOT / "opensource" / sid / "live-specs" / f"{name}.json"))
    return out


def run(cmd: list[str], cwd=None, timeout=900, env=None) -> tuple[str, float]:
    t = time.time()
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **env} if env else None)
    return r.stdout, time.time() - t


GO_BIN = os.environ.get("ATG_GO_BIN", "/usr/local/go1.24.7/bin")


def gosec_dir(src: Path) -> tuple[str, float]:
    """gosec on a copy of one Go module. The module proxy is not reachable here, so the copy is told to use the
    local Go toolchain (its go/toolchain lines are lowered to it) and to load packages without downloading
    dependencies. gosec then still parses every file; rules that need the types of third-party packages may
    miss findings, which the benchmark notes."""
    import shutil
    with tempfile.TemporaryDirectory() as d:
        dst = Path(d) / src.name
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "node_modules", "vendor"))
        for gm in dst.rglob("go.mod"):
            txt = gm.read_text(encoding="utf-8")
            txt = re.sub(r"(?m)^go \d+\.\d+(\.\d+)?$", "go 1.24", txt)
            txt = re.sub(r"(?m)^toolchain .*$", "", txt)
            gm.write_text(txt, encoding="utf-8")
        env = {"PATH": f"{GO_BIN}:{os.environ.get('PATH', '')}", "GOTOOLCHAIN": "local",
               "GOFLAGS": "-mod=mod", "GOPROXY": "off"}
        return run([str(T / "bin/gosec"), "-fmt", "json", "-quiet", "-no-fail", "./..."], cwd=dst, env=env)


def k8s_target(kind: str, name: str) -> str:
    kind = kind.lower()
    if kind == "configmap":
        return f"configmap:{name}"
    if kind == "secret":
        return f"secret:{name}"
    return f"svc:{name}"


# ---------------------------------------------------------------- the tools
def tool_checkov(sid: str) -> dict:
    files = manifest_files(sid)
    compose = system(sid).get("artifacts", {}).get("compose")
    if not files and not compose:
        return {"applicable": False, "why": "no Kubernetes manifests"}
    pairs, raw, secs = set(), Counter(), 0.0
    if files:
        args = sum((["--file", str(f)] for f in files), [])
        out, dt = run([str(T / "venv/bin/checkov"), *args, "--framework", "kubernetes", "secrets", "-o", "json", "--quiet",
                       "--skip-download"])
        secs += dt
        docs = json.loads(out or "[]")
        for d in docs if isinstance(docs, list) else [docs]:
            for c in (d.get("results") or {}).get("failed_checks", []):
                raw[c["check_id"]] += 1
                if d.get("check_type") == "secrets":
                    pairs.add(("C7", _object_at(Path(c["file_abs_path"]), c["file_line_range"][0])))
                elif c["check_id"] in CHECKOV:
                    kind, _, name = c["resource"].partition(".")
                    pairs.add((CHECKOV[c["check_id"]], k8s_target(kind, name.split(".", 1)[-1])))
    elif compose:
        return {"applicable": False, "why": "Checkov has no Docker Compose checks"}
    return {"applicable": True, "pairs": sorted(pairs), "raw": dict(raw), "seconds": round(secs, 2),
            "findings": sum(raw.values())}


def _object_at(f: Path, line: int) -> str:
    """The Kubernetes object (or compose service) a file line belongs to."""
    lines = f.read_text(encoding="utf-8").splitlines()
    start = 0
    for i in range(min(line, len(lines)) - 1, -1, -1):
        if lines[i].strip() == "---":
            start = i + 1
            break
    try:
        doc = yaml.safe_load("\n".join(lines[start:]).split("\n---")[0]) or {}
    except yaml.YAMLError:
        doc = {}
    if isinstance(doc, dict) and doc.get("kind"):
        return k8s_target(doc["kind"], (doc.get("metadata") or {}).get("name", "?"))
    return f"file:{f.name}"


def tool_kubescape(sid: str) -> dict:
    files = manifest_files(sid)
    if not files:
        return {"applicable": False, "why": "reads Kubernetes manifests only (this system ships Docker Compose)"}
    with tempfile.TemporaryDirectory() as d:
        for i, f in enumerate(files):
            (Path(d) / f"{i:03d}-{f.name}").write_bytes(f.read_bytes())
        outf = Path(d) / "out.json"
        _, dt = run([str(T / "bin/kubescape"), "scan", d, "--format", "json", "--output", str(outf), "--keep-local"],
                    timeout=1200)
        doc = json.loads(outf.read_text()) if outf.exists() else {}
    res = {r["resourceID"]: r for r in doc.get("results", [])}
    names = {}
    for r in doc.get("resources", []):
        obj = r.get("object") or {}
        names[r["resourceID"]] = (obj.get("kind", ""), (obj.get("metadata") or {}).get("name", ""))
    pairs, raw = set(), Counter()
    for rid, r in res.items():
        for c in r.get("controls", []):
            if (c.get("status") or {}).get("status") == "failed":
                raw[c["controlID"]] += 1
                cat = KUBESCAPE.get(c["controlID"])
                if cat:
                    kind, name = names.get(rid, ("", rid.rsplit("/", 1)[-1]))
                    pairs.add((cat, k8s_target(kind, name)))
    return {"applicable": True, "pairs": sorted(pairs), "raw": dict(raw), "seconds": round(dt, 2), "findings": sum(raw.values())}


def tool_kubelinter(sid: str) -> dict:
    files = manifest_files(sid)
    if not files:
        return {"applicable": False, "why": "reads Kubernetes manifests only"}
    out, dt = run([str(T / "bin/kube-linter"), "lint", *map(str, files), "--format", "json"])
    doc = json.loads(out or "{}")
    pairs, raw = set(), Counter()
    for r in doc.get("Reports") or []:
        raw[r["Check"]] += 1
        o = r["Object"]["K8sObject"]
        if r["Check"] in KUBELINTER:
            pairs.add((KUBELINTER[r["Check"]], k8s_target(o["GroupVersionKind"]["Kind"], o["Name"])))
    return {"applicable": True, "pairs": sorted(pairs), "raw": dict(raw), "seconds": round(dt, 2), "findings": sum(raw.values())}


def tool_polaris(sid: str) -> dict:
    files = manifest_files(sid)
    if not files:
        return {"applicable": False, "why": "reads Kubernetes manifests only"}
    pairs, raw, secs = set(), Counter(), 0.0
    with tempfile.TemporaryDirectory() as d:
        for i, f in enumerate(files):
            (Path(d) / f"{i:03d}-{f.name}").write_bytes(f.read_bytes())
        out, dt = run([str(T / "bin/polaris"), "audit", "--audit-path", d, "--format", "json"])
        secs += dt
    doc = json.loads(out or "{}")
    for r in doc.get("Results") or []:
        results = dict(r.get("Results") or {})
        pod = r.get("PodResult") or {}
        results.update(pod.get("Results") or {})
        for cr in pod.get("ContainerResults") or []:
            results.update(cr.get("Results") or {})
        for k, v in results.items():
            if not v.get("Success", True):
                raw[k] += 1
                if k in POLARIS:
                    pairs.add((POLARIS[k], k8s_target(r["Kind"], r["Name"])))
    return {"applicable": True, "pairs": sorted(pairs), "raw": dict(raw), "seconds": round(secs, 2), "findings": sum(raw.values())}


def tool_spectral(sid: str) -> dict:
    specs = spec_files(sid)
    if not specs:
        return {"applicable": False, "why": "no API document to lint"}
    rules = T / "owasp.spectral.yaml"
    rules.write_text('extends: ["@stoplight/spectral-owasp-ruleset"]\n')
    pairs, raw, secs = set(), Counter(), 0.0
    for svc, f in specs:
        out, dt = run([str(T / "node_modules/.bin/spectral"), "lint", str(f), "--ruleset", str(rules), "-f", "json", "--quiet"],
                      cwd=T)
        secs += dt
        try:
            items = json.loads(out or "[]")
        except ValueError:
            items = []
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for it in items:
            code = str(it.get("code"))
            raw[code] += 1
            path = it.get("path") or []
            ep = None
            if len(path) >= 3 and path[0] == "paths" and str(path[2]).lower() in ("get", "post", "put", "patch", "delete"):
                ep = f"ep:{svc}:{path[2].upper()}:{re.sub(r'{[^}]*}', '{}', path[1])}"
            if re.search(r"api2.*(protection|write-restricted|read-restricted)", code) and ep:
                pairs.add(("A1", ep))
            elif re.search(r"api4.*rate-limit", code) and ep and re.search(r"(login|token|auth|session)", ep):
                pairs.add(("A6", ep))
            elif re.search(r"(api8|https|hosts-https)", code):
                pairs.add(("C8", f"svc:{svc}"))
        _ = doc
    return {"applicable": True, "pairs": sorted(pairs), "raw": dict(raw), "seconds": round(secs, 2), "findings": sum(raw.values())}


def _sast(sid: str, tool: str) -> dict:
    s = system(sid)
    lang = LANG_TOOL[tool]
    targets = {n: up(sid) / p for n, p in SOURCES[sid].items()
               if (s["services"].get(n, {}).get("language") or OTHER_LANG.get(sid, {}).get(n, "")) == lang}
    total = len(SOURCES[sid])
    if not targets:
        return {"applicable": False, "why": f"no {lang} service", "covered": 0, "services": total}
    pairs, raw, secs = set(), Counter(), 0.0
    for name, d in targets.items():
        if tool == "bandit":
            out, dt = run([str(T / "venv/bin/bandit"), "-r", str(d), "-f", "json", "-q"])
            items = [(r["test_id"], r["test_name"]) for r in json.loads(out or '{"results": []}').get("results", [])]
        elif tool == "gosec":
            out, dt = gosec_dir(d)
            try:
                items = [(i["rule_id"], i["details"]) for i in json.loads(out or "{}").get("Issues") or []]
            except ValueError:
                items = []
        else:
            out, dt = run([str(T / "venv/bin/njsscan"), "--json", str(d)])
            try:
                doc = json.loads(out or "{}")
                items = [(k, k) for k, v in (doc.get("nodejs") or {}).items() for _ in v.get("files", [])]
            except ValueError:
                items = []
        secs += dt
        for rid, name_ in items:
            raw[rid] += 1
            if re.search(r"(hardcoded|B105|B106|B107|G101|secret)", f"{rid} {name_}", re.I):
                pairs.add(("C7", f"svc:{name}"))
    return {"applicable": True, "pairs": sorted(pairs), "raw": dict(raw), "seconds": round(secs, 2),
            "findings": sum(raw.values()), "covered": len(targets), "services": total}


TOOLS = {"checkov": tool_checkov, "kubescape": tool_kubescape, "kube-linter": tool_kubelinter, "polaris": tool_polaris,
         "spectral": tool_spectral, "bandit": lambda s: _sast(s, "bandit"), "gosec": lambda s: _sast(s, "gosec"),
         "njsscan": lambda s: _sast(s, "njsscan")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("systems", nargs="*", default=SYSTEMS)
    ap.add_argument("--tools", default=",".join(TOOLS))
    a = ap.parse_args()
    for tool in a.tools.split(","):
        (OUT / tool).mkdir(parents=True, exist_ok=True)
        for sid in a.systems:
            res = TOOLS[tool](sid)
            if res.get("applicable"):
                al = sc.aliases(sid)
                pairs = {(c, sc.norm(t, al)) for c, t in res["pairs"]}
                res["pairs"] = sorted(pairs)
                res["score"] = sc.score(sid, pairs, SCOPE.get(tool))
            (OUT / tool / f"{sid}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
            msg = (f"labels {res['score']['found']}/{res['score']['labels']}, matching {res['score']['confirmed']}/"
                   f"{res['score']['reported']}, {res['findings']} findings, {res['seconds']} s") if res.get("applicable") \
                else f"n/a ({res['why']})"
            print(f"{tool:12s} {sid:18s} {msg}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
