"""
ATG vs OWASP ZAP on the same ShopLite build (point 4 of the review: speed and effectiveness
against another tool).

ZAP is the most used free API scanner. It is an active (DAST) tool: it imports the OpenAPI
documents and sends attack requests to the running services. ATG is passive: it reads the
traffic the customers already send, the specs, the manifests and the traces. Both get the
same starting knowledge: the OpenAPI documents ATG used, and network access to the services.

ZAP runs twice:
  gateway    the specs mapped onto the public gateway routes (what an outside tester sees)
  internal   the specs of each service, scanned directly inside the cluster network
             (the position ATG's sidecar has)

ZAP gets no login: the review rules for this project do not allow creating credentials or
tokens in the harness, so it scans as an anonymous client, as ZAP's API scan does by default.

The services publish OpenAPI 3.1 (FastAPI's default). ZAP 2.16's OpenAPI add-on does not fill
parameter values from 3.1 schemas (it sent /users//addresses and ?user_id= with empty values;
results/zap/zap-openapi31-as-served.json), so each document is converted to 3.0.3 before import
(as_openapi30). These documents use nothing 3.0 cannot express, so nothing is lost.

    # ShopLite (vulnerable) and the ATG platform running, scan 1 done (START steps 1-4)
    python bench/compare_zap.py --zap /path/to/ZAP_2.16.1 --atg-scan atg-scan/   # analysis.json, eujf.json, ...
    python bench/compare_zap.py --report                                          # tables from results/zap/zap.json

Scoring is the same as Table 16: a weakness counts as found when a tool reports it on the
right endpoint (or service) under a matching category. ZAP alerts are matched by CWE family
(see FAMILY); the mapping and the judgement of every ZAP alert type are written out below.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "results" / "zap"
ZAP_PORT = 8090
API = f"http://127.0.0.1:{ZAP_PORT}"
SERVICES = {"api-gateway": 8000, "user-service": 8001, "order-service": 8002, "payment-service": 8003}
# public prefix -> (service, prefix the gateway strips), from demo_target/k8s/gateway.yaml
GATEWAY_BASE = {"user-service": "/api", "order-service": "/api", "payment-service": "/api/payments"}

# ZAP alert CWE -> the rule families of ShopLite's planted list it can stand for
FAMILY = {
    "authz": ({284, 285, 287, 306, 639, 862, 863}, {"TS-01", "TS-03", "TS-08", "API1", "API5"}),
    "exposure": ({200, 201, 209, 213, 215, 359, 489, 497, 532, 538, 548}, {"API3", "API8-DEBUG"}),
    "brute_force": ({307}, {"TS-07"}),
    "resources": ({400, 770, 789}, {"API4"}),
}


# ---------------------------------------------------------------- ZAP
def zap(path: str, **params) -> dict:
    r = httpx.get(f"{API}/JSON/{path}/", params=params, timeout=120, trust_env=False)
    r.raise_for_status()
    return r.json()


def start_zap(zap_home: Path, workdir: Path) -> subprocess.Popen:
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [str(zap_home / "zap.sh"), "-daemon", "-host", "127.0.0.1", "-port", str(ZAP_PORT), "-dir", str(workdir),
           "-silent", "-config", "api.disablekey=true", "-config", "database.recoverylog=false"]
    proc = subprocess.Popen(cmd, stdout=(workdir / "zap.out").open("w"), stderr=subprocess.STDOUT)
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            print("ZAP", zap("core/view/version")["version"], flush=True)
            return proc
        except (httpx.HTTPError, ValueError):
            time.sleep(2)
    proc.kill()
    raise SystemExit("ZAP did not start; see " + str(workdir / "zap.out"))


def wait_passive() -> None:
    while int(zap("pscan/view/recordsToScan")["recordsToScan"]) > 0:
        time.sleep(1)


def active_scan(base: str) -> None:
    sid = zap("ascan/action/scan", url=base, recurse="true", inScopeOnly="false")["scan"]
    while int(zap("ascan/view/status", scanId=sid)["status"]) < 100:
        time.sleep(2)


def container_ip(name: str) -> str:
    out = subprocess.run(["docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "customer-net").IPAddress}}', name],
                         capture_output=True, text=True, check=True).stdout.strip()
    if not out:
        raise SystemExit(f"{name} is not on customer-net; start ShopLite first (START steps 1-4)")
    return out


def as_openapi30(node):
    """OpenAPI 3.1 -> 3.0.3 for the constructs FastAPI emits: anyOf [X, null] -> X + nullable,
    examples [..] -> example, const -> enum."""
    if isinstance(node, list):
        return [as_openapi30(x) for x in node]
    if not isinstance(node, dict):
        return node
    out = {k: as_openapi30(v) for k, v in node.items()}
    if out.get("openapi", "").startswith("3.1"):
        out["openapi"] = "3.0.3"
    any_of = out.get("anyOf")
    if isinstance(any_of, list) and any(isinstance(x, dict) and x.get("type") == "null" for x in any_of):
        rest = [x for x in any_of if not (isinstance(x, dict) and x.get("type") == "null")]
        del out["anyOf"]
        if len(rest) == 1:
            out.update(rest[0])
        else:
            out["anyOf"] = rest
        out["nullable"] = True
    if isinstance(out.get("examples"), list) and "in" not in out:
        ex = out.pop("examples")
        if ex:
            out["example"] = ex[0]
    if "const" in out:
        out["enum"] = [out.pop("const")]
    return out


def fetch_specs(ips: dict[str, str], folder: Path) -> dict[str, Path]:
    """The OpenAPI documents ATG used: each service's live /openapi.json plus the payment spec file."""
    specs = {}
    for svc, port in SERVICES.items():
        try:
            r = httpx.get(f"http://{ips[svc]}:{port}/openapi.json", timeout=5, trust_env=False)
            if r.status_code == 200 and "paths" in r.json():
                p = folder / f"{svc}.json"
                p.write_text(json.dumps(as_openapi30(r.json()), indent=1), encoding="utf-8")
                specs[svc] = p
        except (httpx.HTTPError, ValueError):
            pass
    specs["payment-service (file)"] = ROOT / "demo_target" / "specs" / "payment-service.v1.yaml"
    return specs


def run_mode(mode: str, ips: dict[str, str], specs: dict[str, Path]) -> dict:
    zap("core/action/newSession", overwrite="true")
    t0 = time.perf_counter()
    bases = []
    for name, f in specs.items():
        svc = name.split(" ")[0]
        if mode == "internal":
            target = f"http://{ips[svc]}:{SERVICES[svc]}"
        else:
            if svc not in GATEWAY_BASE:
                continue  # the gateway's own document is about the gateway, not a public route
            target = f"http://{ips['api-gateway']}:8000{GATEWAY_BASE[svc]}"
        res = zap("openapi/action/importFile", file=str(f), target=target)
        print(f"  [{mode}] import {name} -> {target}: {res}", flush=True)
        base = f"http://{urlsplit(target).netloc}"
        if base not in bases:
            bases.append(base)
    t_import = time.perf_counter()
    wait_passive()
    for base in bases:
        active_scan(base)
    wait_passive()
    t_end = time.perf_counter()
    alerts = []
    for base in bases:
        start = 0
        while True:
            page = zap("core/view/alerts", baseurl=base, start=start, count=500)["alerts"]
            alerts += page
            if len(page) < 500:
                break
            start += 500
    urls = []
    for base in bases:
        urls += zap("core/view/urls", baseurl=base)["urls"]
    messages = sum(int(zap("core/view/numberOfMessages", baseurl=b)["numberOfMessages"]) for b in bases)
    return {"mode": mode, "bases": bases, "import_s": round(t_import - t0, 1), "total_s": round(t_end - t0, 1),
            "messages": messages, "urls": sorted(set(urls)),
            "alerts": [{k: a.get(k) for k in ("pluginId", "alert", "risk", "confidence", "cweid", "wascid", "method", "url",
                                               "param", "attack", "evidence")} for a in alerts]}


# ---------------------------------------------------------------- scoring
def endpoint_index(eujf: dict) -> list[tuple[str, str, str, re.Pattern]]:
    out = []
    for e in eujf["endpoints"]:
        rx = re.compile("^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(e["path"])) + "/?$")
        out.append((e["service"], e["method"], e["path"], rx))
    return out


def locate(url: str, method: str, mode: str, ips: dict[str, str], index) -> tuple[str, str, str] | None:
    u = urlsplit(url)
    host = u.hostname
    svc_by_ip = {ip: s for s, ip in ips.items()}
    svc, path = svc_by_ip.get(host), u.path
    if svc == "api-gateway":
        for s, prefix in sorted(GATEWAY_BASE.items(), key=lambda x: -len(x[1])):
            if path.startswith(prefix + "/"):
                cand = path[len(prefix):]
                hit = next(((sv, m, p) for sv, m, p, rx in index if sv == s and m == method and rx.match(cand)), None)
                if hit:
                    return hit
        svc = "api-gateway"
    for sv, m, p, rx in index:
        if sv == svc and m == method and rx.match(path):
            return (sv, m, p)
    return None


def cwe_family(cwe) -> str | None:
    try:
        c = int(cwe)
    except (TypeError, ValueError):
        return None
    return next((f for f, (cwes, _) in FAMILY.items() if c in cwes), None)


def score(result: dict, ips: dict[str, str], eujf: dict, atg_analysis: dict) -> dict:
    from bench.common import shape
    from bench.evaluate_threat import SHOPLITE_PLANTED, SHOPLITE_UNCOVERED, fkey, simple_target
    index = endpoint_index(eujf)
    planted = SHOPLITE_PLANTED
    total = len(planted) + len(SHOPLITE_UNCOVERED)

    # ATG, same scoring as Table 16
    id2key = {e["id"]: (e["service"], e["method"], shape(e["path"])) for e in eujf["endpoints"]}
    atg_got = {simple_target(fkey(f, id2key)) for f in atg_analysis["findings"]}
    atg_found = atg_got & planted

    def items(found):  # JSON-friendly: [rule, service] or [rule, [service, method, path]]
        return sorted([r, list(t) if isinstance(t, tuple) else t] for r, t in found)

    out = {"planted_total": total, "atg": {"found": len(atg_found), "findings": len(atg_analysis["findings"]),
                                           "extra": len(atg_got - planted), "found_items": items(atg_found)}}
    for mode in ("gateway", "internal"):
        r = result.get(mode)
        if not r:
            continue
        found, types = set(), {}
        for a in r["alerts"]:
            loc = locate(a["url"], a["method"], mode, ips, index)
            fam = cwe_family(a["cweid"])
            key = (a["alert"], a["risk"], a["cweid"])
            t = types.setdefault(key, {"alert": a["alert"], "risk": a["risk"], "cwe": a["cweid"], "instances": 0,
                                       "endpoints": set(), "family": fam})
            t["instances"] += 1
            if loc:
                t["endpoints"].add(f"{loc[1]} {loc[2]} ({loc[0]})")
            if fam and loc:
                rules = FAMILY[fam][1]
                for rule, tgt in planted:
                    if rule in rules and tgt == (loc[0], loc[1], shape(loc[2])):
                        found.add((rule, tgt))
        touched = set()
        for u in r["urls"]:
            m, _, url = u.partition(" ") if " " in u else ("GET", "", u)
            for meth in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                loc = locate(url, meth, mode, ips, index)
                if loc:
                    touched.add(loc)
        out[mode] = {"found": len(found), "found_items": items(found), "messages": r["messages"],
                     "total_s": r["total_s"], "alerts": len(r["alerts"]),
                     "endpoints_touched": len(touched), "endpoints_total": len(eujf["endpoints"]),
                     "alert_types": [{**t, "endpoints": sorted(t["endpoints"])} for t in types.values()]}
    out["atg"]["endpoints"] = len(eujf["endpoints"])
    return out


# ---------------------------------------------------------------- main
def rescore(atg_scan: Path) -> None:
    """Score an earlier ZAP run again (results/zap/zap.json keeps the raw alerts and URLs)."""
    f = OUT / "zap.json"
    result = json.loads(f.read_text(encoding="utf-8"))
    eujf = json.loads((atg_scan / "eujf.json").read_text(encoding="utf-8"))
    analysis = json.loads((atg_scan / "analysis.json").read_text(encoding="utf-8"))
    if (atg_scan / "atg.json").exists():
        result["atg"] = json.loads((atg_scan / "atg.json").read_text(encoding="utf-8"))
    result["score"] = score(result, result["ips"], eujf, analysis)
    f.write_text(json.dumps(result, indent=1, default=sorted), encoding="utf-8")


def run(zap_home: Path, atg_scan: Path) -> None:
    ips = {s: container_ip(f"shoplite-{s}-1") for s in SERVICES}
    print("ShopLite on customer-net:", ips, flush=True)
    work = Path(tempfile.mkdtemp(prefix="zap-"))
    specs = fetch_specs(ips, work)
    print("specs given to ZAP:", {k: str(v) for k, v in specs.items()}, flush=True)
    proc = start_zap(zap_home, work / "home")
    try:
        result = {"zap_version": zap("core/view/version")["version"], "specs": sorted(specs)}
        for mode in ("gateway", "internal"):
            print(f"[{mode}] scanning ...", flush=True)
            result[mode] = run_mode(mode, ips, specs)
            print(f"[{mode}] {result[mode]['total_s']} s, {result[mode]['messages']} requests, "
                  f"{len(result[mode]['alerts'])} alerts", flush=True)
    finally:
        try:
            zap("core/action/shutdown")
        except httpx.HTTPError:
            pass
        proc.wait(timeout=60)
        shutil.rmtree(work, ignore_errors=True)
    eujf = json.loads((atg_scan / "eujf.json").read_text(encoding="utf-8"))
    analysis = json.loads((atg_scan / "analysis.json").read_text(encoding="utf-8"))
    atg_meta = json.loads((atg_scan / "atg.json").read_text(encoding="utf-8")) if (atg_scan / "atg.json").exists() else {}
    result["ips"] = ips
    result["atg"] = atg_meta
    result["score"] = score(result, ips, eujf, analysis)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "zap.json").write_text(json.dumps(result, indent=1, default=sorted), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zap", type=Path, help="folder of the unpacked ZAP release (has zap.sh)")
    ap.add_argument("--atg-scan", type=Path, help="folder with ATG's analysis.json and eujf.json of the same build")
    ap.add_argument("--rescore", action="store_true", help="score results/zap/zap.json again, no new ZAP run")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    if a.rescore:
        rescore(a.atg_scan)
    elif not a.report:
        run(a.zap, a.atg_scan)
    from bench.report_zap import report
    report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
