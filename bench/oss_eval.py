"""
Evaluation runs on the ten open-source systems (Section V of the report). For each system, as START
does it: start the system's Docker (stand-in services), start ATG on its network, run its users,
scan once. Then, while both are still running:

  1. keep the scan's Phase 1 output per source, its EUJF and its analysis
     (results/opensource/eval/<tag>/<id>/live/scans/..., runs/...): the input of the per-source,
     reconciliation and observation-window tables (bench/oss_report.py)
  2. sidecar overhead: the same GET sent N times straight to the system's entry service and N
     times through ATG's sidecar, from inside the network
  3. OWASP ZAP (DAST baseline) against the same system, from the network position ATG has:
     spider the entry service, import every API document ATG used at the service's own address,
     active-scan everything ZAP found (bench/compare_zap.py has the ZAP helpers)

    python bench/oss_eval.py --zap /var/tmp/zap/ZAP_2.16.1             all ten, base run
    python bench/oss_eval.py bookinfo --no-zap                          one, no ZAP
    python bench/oss_eval.py --tag fixed --config-root results/opensource/fixes --no-zap --no-overhead
                                                                        rescan with the fixed deployment files

Writes results/opensource/eval/<tag>/<id>.json (summary) and the folder <id>/ (scan output).
"""
from __future__ import annotations

import argparse
import glob
import io
import json
import re
import statistics
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
from fetch import SYSTEMS  # noqa: E402
from run_companies import DUMP, read_env, sh  # noqa: E402

OUT = ROOT / "results" / "opensource" / "eval"

TIMER = r"""
import json, statistics, sys, time, urllib.request
direct, proxied, path, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def t(url):
    s = time.perf_counter()
    try:
        op.open(url, timeout=10).read()
    except Exception:
        pass
    return (time.perf_counter() - s) * 1000
for _ in range(20):            # warm both paths
    t(direct + path); t(proxied + path)
d, p = [], []
for _ in range(n):
    d.append(t(direct + path)); p.append(t(proxied + path))
q = lambda xs, k: sorted(xs)[int(k * (len(xs) - 1))]
print(json.dumps({"n": n, "path": path, "direct_p50": q(d, .5), "direct_p95": q(d, .95),
                  "sidecar_p50": q(p, .5), "sidecar_p95": q(p, .95)}))
"""


def compose_ps_ip(comp: list[str], service: str, network: str) -> str:
    cid = subprocess.run(comp + ["ps", "-q", service], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return subprocess.run(["docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % network, cid],
                          capture_output=True, text=True, check=True).stdout.strip()


def copy_work(env: dict, dest: Path) -> None:
    """The scan's in-memory folder (/work in the atg container): Phase 1 output, EUJF, analysis."""
    r = subprocess.run(["docker", "compose", "exec", "-T", "atg", "tar", "-C", "/work", "-cf", "-", "live/scans", "runs"],
                       cwd=ROOT, env={**__import__("os").environ, **env}, capture_output=True, check=True)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(r.stdout)) as t:
        t.extractall(dest, filter="data")


def probe_path(dump: dict) -> str:
    """A GET operation the gateway serves, with sample values in its path."""
    gets = [e for e in dump["endpoints"] if e["method"] == "GET" and e["public_paths"]]
    gets.sort(key=lambda e: ("{" in e["public_paths"][0], len(e["public_paths"][0])))
    if not gets:
        return "/"
    return re.sub(r"\{[^}]+\}", "1", gets[0]["public_paths"][0])


# ---------------------------------------------------------------- ZAP
def zap_specs(sid: str, cfg_dir: Path, work: Path) -> list[tuple[Path, str]]:
    """The API documents ATG used: the system's spec files and the live documents the services served."""
    import compare_zap as cz
    tcfg = yaml.safe_load((cfg_dir / "atg-target.yaml").read_text(encoding="utf-8"))
    out = []
    folder = work / "zap-specs"
    folder.mkdir(parents=True, exist_ok=True)
    for i, f in enumerate(tcfg["sources"]["openapi"].get("spec_files", [])):
        src = cfg_dir / f["path"]
        doc = yaml.safe_load(src.read_text(encoding="utf-8"))
        p = folder / f"{i}-{f['service']}.json"
        p.write_text(json.dumps(cz.as_openapi30(doc), indent=1), encoding="utf-8")
        out.append((p, f["service"]))
    return out


def run_zap(sid: str, env: dict, comp: list[str], cfg_dir: Path, work: Path) -> dict:
    import compare_zap as cz
    net = env["TARGET_NETWORK"]
    gw = re.match(r"https?://([^:/]+):?(\d+)?", env["TARGET_GATEWAY"])
    entry_svc, entry_port = gw.group(1), gw.group(2) or "80"
    tcfg = yaml.safe_load((cfg_dir / "atg-target.yaml").read_text(encoding="utf-8"))
    hostport = {k.split(":")[0]: k.split(":")[1] for k in tcfg["target"]["service_map"]}
    services = sorted(set(tcfg["target"]["service_map"].values()) | {entry_svc})
    ips = {}
    for s in services:
        try:
            ips[s] = compose_ps_ip(comp, s, net)
        except subprocess.CalledProcessError:
            pass
    cz.zap("core/action/newSession", overwrite="true")
    cz.zap("spider/action/setOptionMaxDuration", Integer="2")
    cz.zap("ascan/action/setOptionMaxScanDurationInMins", Integer="6")
    cz.zap("ascan/action/setOptionMaxRuleDurationInMins", Integer="1")
    t0 = time.perf_counter()
    entry = f"http://{ips[entry_svc]}:{entry_port}"
    bases = [entry]
    for f, svc in zap_specs(sid, cfg_dir, work):
        if svc not in ips:
            continue
        target = f"http://{ips[svc]}:{hostport.get(svc, entry_port)}"
        res = cz.zap("openapi/action/importFile", file=str(f), target=target)
        print(f"   zap: import {f.name} -> {target}: {str(res)[:120]}", flush=True)
        if target not in bases:
            bases.append(target)
    # the live documents ATG found (springdoc /v3/api-docs and the like), at the service's address
    raw = next(iter(sorted((OUT / work.parent.name / sid).glob("live/scans/*/raw/openapi.json"))), None) if False else \
        next(iter(sorted(work.glob("live/scans/*/raw/openapi.json"))), None)
    for rec in (json.loads(raw.read_text())["records"] if raw else []):
        loc = rec.get("location") or ""
        m = re.match(r"https?://([^:/]+)(:\d+)?(/.*)", loc)
        if rec.get("kind") == "spec" and m and m.group(1) in ips:
            url = f"http://{ips[m.group(1)]}{m.group(2) or ''}{m.group(3)}"
            res = cz.zap("openapi/action/importUrl", url=url, hostOverride=f"{ips[m.group(1)]}{m.group(2) or ''}")
            print(f"   zap: import {loc} -> {url}: {str(res)[:120]}", flush=True)
            base = f"http://{ips[m.group(1)]}{m.group(2) or ''}"
            if base not in bases:
                bases.append(base)
    sid_sp = cz.zap("spider/action/scan", url=entry + "/", recurse="true")["scan"]
    while int(cz.zap("spider/view/status", scanId=sid_sp)["status"]) < 100:
        time.sleep(2)
    cz.wait_passive()
    for b in bases:
        cz.active_scan(b)
    cz.wait_passive()
    total = time.perf_counter() - t0
    alerts, urls = [], []
    for b in bases:
        start = 0
        while True:
            page = cz.zap("core/view/alerts", baseurl=b, start=start, count=500)["alerts"]
            alerts += page
            if len(page) < 500:
                break
            start += 500
        urls += cz.zap("core/view/urls", baseurl=b)["urls"]
    messages = sum(int(cz.zap("core/view/numberOfMessages", baseurl=b)["numberOfMessages"]) for b in bases)
    by_ip = {v: k for k, v in ips.items()}
    return {"bases": bases, "ips": ips, "by_ip": by_ip, "total_s": round(total, 1), "messages": messages,
            "urls": sorted(set(urls)),
            "alerts": [{k: a.get(k) for k in ("pluginId", "alert", "risk", "confidence", "cweid", "method", "url", "param")}
                       for a in alerts]}


def inventory_openapi(eujf: dict, folder: Path) -> list[tuple[Path, str]]:
    """ATG's inventory as one OpenAPI 3.0 document per service (method, path, path parameters,
    and the request fields ATG saw), so ZAP can be given every operation ATG found."""
    folder.mkdir(parents=True, exist_ok=True)
    by_svc: dict[str, dict] = {}
    for e in eujf["endpoints"]:
        params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string", "example": "1"}}
                  for n in re.findall(r"\{([^}]+)\}", e["path"])]
        params += [{"name": q if isinstance(q, str) else q.get("name", "q"), "in": "query", "schema": {"type": "string", "example": "1"}}
                   for q in e.get("query_params") or []]
        op = {"responses": {"200": {"description": "ok"}}}
        if params:
            op["parameters"] = params
        fields = ((e.get("request") or {}).get("fields") or []) if isinstance(e.get("request"), dict) else []
        if e["method"] in ("POST", "PUT", "PATCH"):
            props = {f if isinstance(f, str) else f.get("name", "field"): {"type": "string", "example": "a"} for f in fields} or {"value": {"type": "string"}}
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": props}}}}
        by_svc.setdefault(e["service"], {}).setdefault(e["path"], {})[e["method"].lower()] = op
    out = []
    for svc, paths in by_svc.items():
        p = folder / f"inventory-{svc}.json"
        p.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": f"{svc} (ATG inventory)", "version": "1"},
                                 "paths": paths}, indent=1), encoding="utf-8")
        out.append((p, svc))
    return out


def run_zap_inventory(sid: str, tag: str) -> dict:
    """ZAP given every operation ATG found (the base scan's EUJF), at each service's own address."""
    import compare_zap as cz
    env = read_env(sid, "opensource")
    cfg_dir = ROOT / "opensource" / sid
    comp = ["docker", "compose", "-f", f"opensource/{sid}/docker-compose.yml"]
    eujf = json.loads(Path(sorted(glob.glob(str(OUT / "base" / sid / "runs" / "*" / "eujf.json")))[-1]).read_text())
    sh(["docker", "compose", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    sh(comp + ["up", "-d", "--build", "--wait"], env, capture=True)
    sh(["docker", "compose", "up", "-d", "--build", "--wait"], env, capture=True)   # the sidecar carries the east-west calls
    try:
        net = env["TARGET_NETWORK"]
        tcfg = yaml.safe_load((cfg_dir / "atg-target.yaml").read_text(encoding="utf-8"))
        hostport = {k.split(":")[0]: k.split(":")[1] for k in tcfg["target"]["service_map"]}
        cz.zap("core/action/newSession", overwrite="true")
        cz.zap("ascan/action/setOptionMaxScanDurationInMins", Integer="6")
        cz.zap("ascan/action/setOptionMaxRuleDurationInMins", Integer="1")
        ips, bases = {}, []
        t0 = time.perf_counter()
        for f, svc in inventory_openapi(eujf, OUT / tag / sid / "zap-inventory"):
            try:
                ips[svc] = compose_ps_ip(comp, svc, net)
            except subprocess.CalledProcessError:
                continue
            target = f"http://{ips[svc]}:{hostport.get(svc, '8080')}"
            cz.zap("openapi/action/importFile", file=str(f), target=target)
            bases.append(target)
        cz.wait_passive()
        for b in bases:
            cz.active_scan(b)
        cz.wait_passive()
        total = time.perf_counter() - t0
        alerts, urls = [], []
        for b in bases:
            alerts += cz.zap("core/view/alerts", baseurl=b, start=0, count=5000)["alerts"]
            urls += cz.zap("core/view/urls", baseurl=b)["urls"]
        messages = sum(int(cz.zap("core/view/numberOfMessages", baseurl=b)["numberOfMessages"]) for b in bases)
        res = {"system": sid, "bases": bases, "ips": ips, "by_ip": {v: k for k, v in ips.items()}, "total_s": round(total, 1),
               "messages": messages, "urls": sorted(set(urls)),
               "alerts": [{k: a.get(k) for k in ("pluginId", "alert", "risk", "confidence", "cweid", "method", "url", "param")}
                          for a in alerts]}
    finally:
        sh(["docker", "compose", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
        sh(comp + ["--profile", "users", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    (OUT / tag / f"{sid}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"   zap+inventory: {res['messages']} requests, {res['total_s']} s, {len(res['alerts'])} alerts", flush=True)
    return res


# ---------------------------------------------------------------- one system
def run_system(sid: str, tag: str, cfg_root: Path | None, do_zap: bool, do_overhead: bool) -> dict:
    env = read_env(sid, "opensource")
    cfg_dir = ROOT / "opensource" / sid
    if cfg_root:
        cfg_dir = (cfg_root / sid).resolve()
        env["TARGET_CONFIG"] = str(cfg_dir)
    comp = ["docker", "compose", "-f", f"opensource/{sid}/docker-compose.yml"]
    sh(["docker", "compose", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    sh(comp + ["--profile", "users", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    t0 = time.time()
    sh(comp + ["up", "-d", "--build", "--wait"], env, capture=True)
    sh(["docker", "compose", "up", "-d", "--build", "--wait"], env, capture=True)
    t_up = time.time() - t0
    users = sh(comp + ["run", "--rm", "users"], env, capture=True).stdout.strip().splitlines()[-1]
    t1 = time.time()
    scan = sh(["docker", "compose", "exec", "-T", "atg", "python", "docker/scan.py", "--label", sid, "--manifests", "k8s"],
              env, capture=True).stdout
    t_scan = time.time() - t1
    dest = OUT / tag / sid
    copy_work(env, dest)
    dump = json.loads(sh(["docker", "compose", "exec", "-T", "atg", "python", "-c", DUMP], env, capture=True).stdout)
    res = {"system": sid, "tag": tag, "users": users, "startup_s": round(t_up, 1), "scan_wall_s": round(t_scan, 1),
           "scan_log": [ln.strip() for ln in scan.splitlines() if ln.strip().startswith(("[ok]", "[fail]", "!", "[scan]"))],
           **dump}
    if do_overhead:
        path = probe_path(dump)
        out = sh(["docker", "compose", "exec", "-T", "atg", "python", "-c", TIMER, env["TARGET_GATEWAY"],
                  "http://atg-proxy:8080", path, "300"], env, capture=True).stdout.strip().splitlines()[-1]
        res["overhead"] = json.loads(out)
        print(f"   overhead {res['overhead']}", flush=True)
    if do_zap:
        res["zap"] = run_zap(sid, env, comp, cfg_dir, dest)
        print(f"   zap: {res['zap']['messages']} requests, {res['zap']['total_s']} s, {len(res['zap']['alerts'])} alerts", flush=True)
    sh(["docker", "compose", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    sh(comp + ["--profile", "users", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    (OUT / tag / f"{sid}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("systems", nargs="*", default=SYSTEMS)
    ap.add_argument("--tag", default="base")
    ap.add_argument("--config-root", type=Path, default=None, help="folder with <id>/ copies of opensource/<id> (fixed files)")
    ap.add_argument("--zap", type=Path, default=None, help="ZAP installation folder (with zap.sh)")
    ap.add_argument("--no-zap", action="store_true")
    ap.add_argument("--no-overhead", action="store_true")
    ap.add_argument("--zap-inventory", action="store_true", help="only ZAP, given ATG's inventory (needs --zap and a base run)")
    a = ap.parse_args()
    (OUT / a.tag).mkdir(parents=True, exist_ok=True)
    proc = None
    if a.zap and not a.no_zap:
        import compare_zap as cz
        proc = cz.start_zap(a.zap, Path("/var/tmp/zap-work"))
    try:
        for sid in a.systems:
            print(f"== {sid}", flush=True)
            t = time.time()
            try:
                if a.zap_inventory:
                    run_zap_inventory(sid, a.tag)
                    continue
                r = run_system(sid, a.tag, a.config_root, bool(proc), not a.no_overhead)
                print(f"   {r['users']} | {r['summary']['findings']} findings, R {r['summary']['total_path_risk']} | "
                      f"{time.time() - t:.0f} s", flush=True)
            except Exception as exc:  # keep going with the next system
                print(f"   FAILED: {exc}"[:2000], flush=True)
    finally:
        if proc:
            try:
                import compare_zap as cz
                cz.zap("core/action/shutdown")
            except Exception:
                proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
