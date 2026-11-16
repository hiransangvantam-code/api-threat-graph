"""
ATG next to the free tools on the ten open-source systems: one set of tables from the saved runs.

    python bench/compare_tools.py                 ATG v1.5 against the tools, v1.4 for before/after
    python bench/compare_tools.py --atg v1.5 --before v1.4

Reads results/opensource/atg-<tag>/<id>.json and results/opensource/tools/<tool>/<id>.json, scores
everything again with the current ground truth (bench/oss_scoring.py), and writes
results/opensource/comparison.md and comparison.json.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
import oss_scoring as sc  # noqa: E402
from fetch import SYSTEMS  # noqa: E402
from run_opensource import atg_pairs  # noqa: E402
from run_tools import LANG_TOOL, SCOPE, SOURCES  # noqa: E402

OUT = ROOT / "results" / "opensource"
TOOLS = ["checkov", "kubescape", "kube-linter", "polaris", "spectral", "bandit", "gosec", "njsscan"]
NAMES = {"atg": "ATG", "checkov": "Checkov", "kubescape": "Kubescape", "kube-linter": "kube-linter", "polaris": "Polaris",
         "spectral": "Spectral (OWASP)", "bandit": "Bandit", "gosec": "gosec", "njsscan": "njsscan"}
ATG_SCOPE = {c for c in sc.ATG_CATS.values() if c}


def labels(sid: str) -> set[tuple[str, str]]:
    gt = json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))
    return {(l["cat"], l["target"]) for l in gt["labels"]}


def found_set(sid: str, pairs: set) -> set:
    s = sc.score(sid, pairs)
    return labels(sid) - {tuple(m) for m in s["missed"]}


# services whose system.yaml entry has another name, or that have no routes there
LANG_OVERRIDE = {("robot-shop", "web"): "JavaScript (browser page)", ("robot-shop", "dispatch"): "Go",
                 ("petclinic", "api-gateway"): "Java", ("piggymetrics", "gateway"): "Java",
                 ("ftgo", "ftgo-api-gateway"): "Java"}
LANG_SCANNER = {"Python": "Bandit", "Go": "gosec", "Node.js": "njsscan"}


def service_languages() -> dict[str, list[tuple[str, str]]]:
    """{system: [(service, language)]} for the 65 services whose code the benchmark reads."""
    import yaml
    out = {}
    for sid in SYSTEMS:
        sv = (yaml.safe_load((ROOT / "opensource" / sid / "system.yaml").read_text(encoding="utf-8")) or {}).get("services", {})
        rows = []
        for name in SOURCES[sid]:
            lang = LANG_OVERRIDE.get((sid, name))
            if not lang:
                for k, v in sv.items():
                    if k == name or name.endswith("-" + k) or name == k.split("/")[-1]:
                        lang = (v or {}).get("language")
                        break
            rows.append((name, lang or "unknown"))
        out[sid] = rows
    return out


K8S_TOOLS = ("checkov", "kubescape", "kube-linter", "polaris")
TOOL_READS = {"atg": "the running system and all its files", "checkov": "Kubernetes files", "kubescape": "Kubernetes files",
              "kube-linter": "Kubernetes files", "polaris": "Kubernetes files", "spectral": "API documents",
              "bandit": "Python code", "gosec": "Go code", "njsscan": "Node.js code"}


def tool_reach(runs: dict) -> dict[str, list[tuple[str, str, str]]]:
    """{tool: [(system, service, language)]}: the services each tool could review in the ten systems."""
    from run_tools import spec_files
    langs = service_languages()
    out = {}
    for t in ["atg"] + TOOLS:
        rows = []
        for sid in SYSTEMS:
            if not (runs[t].get(sid) or {}).get("applicable"):
                continue
            if t == "spectral":
                docs = {svc for svc, _ in spec_files(sid)}
                rows += [(sid, n, l) for n, l in langs[sid] if n in docs]
            elif t in ("bandit", "gosec", "njsscan"):
                rows += [(sid, n, l) for n, l in langs[sid] if LANG_SCANNER.get(l, "").lower() == t]
            else:                      # ATG and the Kubernetes scanners: every service of the system
                rows += [(sid, n, l) for n, l in langs[sid]]
        out[t] = rows
    return out


def atg_resources(d: Path, sid: str, r: dict) -> dict:
    """ATG's CPU time and peak memory for one review: from bench/usage.py (the four containers, by stage) when
    DEMO-ALL recorded it, else from the scan process alone (timings.json)."""
    out = {}
    proc = (r.get("timings") or {}).get("resources") or {}
    u = d / "usage" / f"{sid}.json"
    usage = json.loads(u.read_text(encoding="utf-8")) if u.exists() else None
    scan = (usage or {}).get("stages", {}).get("scan")
    if scan:   # the analysis: the ATG container (scan, Phases 1-4, pages) and PostgreSQL (graph store, path query)
        two = ("atg", "atg-postgres")

        def both(key):
            return round(sum((scan.get(key) or {}).get(c, 0) for c in two), 3)
        out["cpu_s"] = both("cpu_s")
        out["peak_mb"] = round(both("mem_peak_mb"), 1)
        out["scan_wall_s"] = scan["seconds"]
        if "user_s" in scan:
            out["user_s"], out["sys_s"] = both("user_s"), both("kernel_s")
            out["avg_mb"] = round(both("mem_avg_mb"), 1)
            out["processes"] = int(both("pids_peak"))
            out["cores"] = round(out["cpu_s"] / scan["seconds"], 2) if scan["seconds"] else None
        if proc.get("read_mb") is not None:          # the scan process's own reads and writes
            out["read_mb"], out["write_mb"] = proc["read_mb"], proc["write_mb"]
        out["usage"] = usage
    elif proc:
        out["cpu_s"], out["peak_mb"] = proc.get("cpu_s"), proc.get("peak_mb")
    out["process"] = proc
    return out


def zap_runs() -> dict:
    """OWASP ZAP's time, CPU and memory per system, when bench/oss_eval.py --zap-usage has run."""
    d = OUT / "eval" / "zapusage"
    res = {}
    for sid in SYSTEMS:
        f = d / f"{sid}.json"
        if f.exists():
            z = json.loads(f.read_text(encoding="utf-8")).get("zap") or {}
            if z.get("usage"):
                res[sid] = {"applicable": True, "seconds": z["total_s"], "requests": z.get("messages"),
                            **{k: z["usage"].get(k) for k in ("cpu_s", "user_s", "sys_s", "cores", "peak_mb", "avg_mb",
                                                              "read_mb", "write_mb", "processes")}}
    return res


def load(tag: str) -> dict:
    """{tool: {sid: {"applicable", "why", "pairs", "seconds", "findings", "covered", "services"}}}"""
    runs = {"atg": {}}
    d = OUT / f"atg-{tag}"
    for sid in SYSTEMS:
        f = d / f"{sid}.json"
        if f.exists():
            r = json.loads(f.read_text(encoding="utf-8"))
            tm = r.get("timings") or {}
            secs = round(sum(v for k, v in tm.items() if k.endswith("_ms")) / 1000, 3) if tm else r.get("scan_s")
            runs["atg"][sid] = {"applicable": True, "pairs": atg_pairs(r, sc.aliases(sid)), "seconds": secs,
                                "findings": len(r["findings"]), "endpoints": {e["id"] for e in r["endpoints"]},
                                "flows": r.get("flows"), **atg_resources(d, sid, r)}
    for t in TOOLS:
        runs[t] = {}
        for sid in SYSTEMS:
            f = OUT / "tools" / t / f"{sid}.json"
            if f.exists():
                r = json.loads(f.read_text(encoding="utf-8"))
                r["pairs"] = {tuple(p) for p in r.get("pairs", [])}
                runs[t][sid] = r
    return runs


from run_tools import CHECKOV, KUBESCAPE, KUBELINTER, POLARIS, CHECKOV_OPENAPI_HTTP, CHECKOV_OPENAPI_NOAUTH  # noqa: E402
COUNTED = {"checkov": set(CHECKOV) | CHECKOV_OPENAPI_HTTP | CHECKOV_OPENAPI_NOAUTH, "kubescape": set(KUBESCAPE),
           "kube-linter": set(KUBELINTER), "polaris": set(POLARIS)}
COUNTED_RE = {"checkov": lambda k: k.startswith("CKV_SECRET"),
              "spectral": lambda k: bool(re.search(r"(api2.*(protection|write-restricted|read-restricted)|api4.*rate-limit|"
                                                   r"no-server-http|hosts-https)", k)),
              "bandit": lambda k: k in ("B105", "B106", "B107"), "gosec": lambda k: k == "G101"}


CODE_FILE = re.compile(r"\.(py|go|java|js|ts|rb|php|cs|kt)(:|$|\s|-)")


CAT_NAMES_ = sc.CAT_NAMES


def atg_operations(runs: dict) -> dict:
    """{system: (operations in the code, ATG's entries that are one of them, ATG's entries)} from the DEMO-ALL run."""
    out = {}
    for sid, r in runs["atg"].items():
        al = sc.aliases(sid)
        real = {sc.norm(e["id"], al) for e in
                json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))["endpoints"]}
        got = {sc.norm(e, al) for e in r.get("endpoints") or []}
        out[sid] = (len(real), len(real & got), len(got))
    return out


def future_plan(runs: dict) -> list[str]:
    """Measured combinations of tools, what every tool still misses, and the future plan with the most each step
    could add, all counted from the saved runs and the answer keys."""
    gt = {sid: {(l["cat"], l["target"]): l for l in
                json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))["labels"]}
          for sid in SYSTEMS}
    total = sum(len(v) for v in gt.values())

    def fset(t, sid):
        r = runs[t].get(sid)
        return found_set(sid, r["pairs"]) if r and r.get("applicable") else set()

    def union(tools):
        return sum(len(set().union(*[fset(t, sid) for t in tools])) for sid in SYSTEMS)
    k8s = ["polaris", "kubescape", "checkov", "kube-linter"]
    combos = [("ATG alone", ["atg"]), ("ATG + Polaris", ["atg", "polaris"]), ("ATG + Checkov", ["atg", "checkov"]),
              ("ATG + Polaris + Kubescape", ["atg", "polaris", "kubescape"]), ("ATG + the four Kubernetes scanners", ["atg"] + k8s),
              ("ATG + all eight tools", ["atg"] + TOOLS), ("ATG + the three code scanners (Bandit, gosec, njsscan)",
                                                             ["atg", "bandit", "gosec", "njsscan"]),
              ("The eight tools without ATG", TOOLS)]
    out = ["#### Measured: every combination on the same answer key", "",
           "| Combination | Known weaknesses found |", "|---|---:|"]
    for name, tools in combos:
        u = union(tools)
        out.append(f"| {'**' + name + '**' if name == 'ATG alone' else name} | {u}/{total} ({pct(u, total)}) |")

    def is_code(l):
        return l.get("source") == "code review" or bool(CODE_FILE.search(l.get("evidence") or ""))
    miss, miss_code, nobody, nobody_code = Counter(), Counter(), Counter(), Counter()
    for sid in SYSTEMS:
        a = fset("atg", sid)
        anyone = set().union(*[fset(t, sid) for t in ["atg"] + TOOLS])
        for k, l in gt[sid].items():
            if k not in a:
                miss[k[0]] += 1
                miss_code[k[0]] += is_code(l)
            if k not in anyone:
                nobody[k[0]] += 1
                nobody_code[k[0]] += is_code(l)
    allc = sorted(set(miss) | set(nobody), key=lambda c: (c[0], int(c[1:])))
    out += ["", f"Even all nine tools together leave {sum(nobody.values())} of the {total} known weaknesses unfound. "
            "*Proof in the code* means the answer key's evidence for that weakness is a source-code file, so only "
            "something that reads the code could confirm it.", "",
            "| Kind | Missed by ATG | of which proof in the code | Missed by every tool | of which proof in the code |",
            "|---|---:|---:|---:|---:|"]
    for c in allc:
        out.append(f"| {c} {CAT_NAMES_[c]} | {miss[c]} | {miss_code[c]} | {nobody[c]} | {nobody_code[c]} |")
    out.append(f"| **All** | {sum(miss.values())} | {sum(miss_code.values())} | {sum(nobody.values())} | {sum(nobody_code.values())} |")

    # the plan: first without the code, then (second choice) with the code
    ops = atg_operations(runs)
    ops_total = sum(v[0] for v in ops.values())
    ops_found = sum(v[1] for v in ops.values()) if ops else None
    now = union(["atg"])
    a1 = miss["C9"] + miss["C10"]
    a2 = miss["C3"]
    a3 = miss["C7"] - miss_code["C7"] + miss["C8"] - miss_code["C8"]
    b1 = sum(miss_code.values())
    out += ["", "#### Future plan", "",
            "Each step lists the most it could add: the known weaknesses of that kind ATG misses today. They are upper "
            "bounds counted from the answer key, not results; a step is only proven once it is built and measured again, "
            "and because these steps are chosen after seeing ATG's misses on these systems, they would have to be "
            "checked on systems ATG has not seen.", "",
            "**Plan A, first choice: no source code needed.** ATG keeps working from the running system and its files, "
            "so it stays independent of the programming language and works where the code is not available.", "",
            "| Step | What it adds | At most | ATG alone would reach at most |", "|---|---|---:|---:|",
            f"| A1. Container-hardening and service-account-token rules | ATG already reads `readOnlyRootFilesystem`, "
            f"`allowPrivilegeEscalation`, capabilities and `automountServiceAccountToken` from the manifests but has no rule for "
            f"them (C9, C10) | +{a1} | {now + a1}/{total} ({pct(now + a1, total)}) |",
            f"| A2. Resource limits on every service | today ATG reports missing limits only on services the internet reaches "
            f"(API4); an option to report all of them (C3) | +{a2} | {now + a1 + a2}/{total} ({pct(now + a1 + a2, total)}) |",
            f"| A3. More secret and TLS cases in the files | the plaintext-secret and missing-TLS cases ATG misses in "
            f"deployment files (C7, C8) | +{a3} | {now + a1 + a2 + a3}/{total} ({pct(now + a1 + a2 + a3, total)}) |",
            f"| A4. One merged report with a Kubernetes scanner | import Checkov's or Polaris's SARIF into ATG's threat graph "
            f"and hardening report, so the two run as one review | measured today: ATG + Checkov "
            f"{union(['atg', 'checkov'])}/{total} | |",
            "| A5. Longer or guided user sessions | operations nobody calls during the review stay invisible, because "
            "the traffic and traces show only what is used (the operations table in section 3); replaying a fuller user session or the API documents' examples | "
            + (f"+{ops_total - ops_found} operations ({ops_found} to {ops_total} of {ops_total})" if ops_found else "–") + " | |",
            "", "**Plan B, second choice: when the source code is available.** An optional fifth source that reads the "
            "code to list every route, the authentication each one checks, the calls it makes to other services and "
            "to third-party APIs, and admin or debug consoles registered in it. It is a second choice because the code "
            "is often not available to the reviewer (bought or outsourced services, only container images delivered, "
            "code the owner will not share), and because it needs a reader for each language and framework (the ten "
            "systems use eight languages), which gives up ATG's independence from the language. The three free code "
            "scanners show that ordinary code scanning is not enough: they look for coding mistakes, and adding them "
            f"to ATG adds {union(['atg', 'bandit', 'gosec', 'njsscan']) - now} known weaknesses.", "",
            "| Step | What it adds | At most |", "|---|---|---:|",
            f"| B1. Routes from the code | every operation, even one nobody calls during the review | "
            + (f"+{ops_total - ops_found} operations ({ops_total} of {ops_total})" if ops_found else "–") + " |",
            f"| B2. Authentication, calls and consoles from the code | the API-behaviour weaknesses ATG misses today, all of "
            f"which have their proof in the code (A1 no authentication {miss_code['A1']}, A3 admin {miss_code['A3']}, "
            f"A4 debug {miss_code['A4']}, A5 service calls without credentials {miss_code['A5']}, A6 login rate limit "
            f"{miss_code['A6']}, A10 third-party APIs {miss_code['A10']}) and the secret and TLS cases with their proof in "
            f"the code | +{b1} |",
            "",
            "Together the steps of both plans cover every kind of weakness ATG misses today. That does not mean ATG would "
            "find them all: how many each step really finds can only be measured once it is built.", "",
            f"Plan B matters most for the {sum(nobody_code.values())} weaknesses with proof in the code that no tool finds "
            "today: no combination of the tools in this benchmark can find them without reading the code.", ""]
    return out


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "–"


def tally(tool: str, runs: dict) -> dict:
    scope = ATG_SCOPE if tool == "atg" else SCOPE.get(tool, set())
    t = {"ran": 0, "labels": 0, "found": 0, "reported": 0, "confirmed": 0, "in_reach": 0, "in_reach_found": 0,
         "groups": {g: [0, 0] for g in sc.GROUPS}, "cats": {}, "secs": [], "cpu": [], "mem": [], "na": {},
         "res": {k: [] for k in RES_KEYS}}
    for sid in SYSTEMS:
        lab = labels(sid)
        t["labels"] += len(lab)
        for g, cats in sc.GROUPS.items():
            t["groups"][g][0] += sum(1 for l in lab if l[0] in cats)
        for l in lab:
            t["cats"].setdefault(l[0], [0, 0])[0] += 1
        r = runs[tool].get(sid)
        if not r or not r.get("applicable"):
            t["na"][sid] = (r or {}).get("why", "not run").replace(" (this system ships Docker Compose)", "")
            continue
        t["ran"] += 1
        s = sc.score(sid, r["pairs"], scope)
        f = lab - {tuple(m) for m in s["missed"]}
        t["found"] += len(f)
        t["reported"] += s["reported"]
        t["confirmed"] += s["confirmed"]
        t["in_reach"] += s["in_reach"]["labels"]
        t["in_reach_found"] += s["in_reach"]["found"]
        for g, cats in sc.GROUPS.items():
            t["groups"][g][1] += sum(1 for l in f if l[0] in cats)
        for l in f:
            t["cats"][l[0]][1] += 1
        if r.get("seconds") is not None:
            t["secs"].append(r["seconds"])
        if r.get("cpu_s") is not None:
            t["cpu"].append(r["cpu_s"])
        if r.get("peak_mb") is not None:
            t["mem"].append(r["peak_mb"])
        for k in RES_KEYS:
            if r.get(k) is not None:
                t["res"][k].append(r[k])
    return t


RES_KEYS = ("cpu_s", "user_s", "sys_s", "cores", "peak_mb", "avg_mb", "read_mb", "write_mb", "processes")


def fs(v) -> str:
    """seconds, rounded for reading"""
    return "–" if v is None else f"{v:.2f} s" if v < 1 else f"{v:.1f} s" if v < 100 else f"{v:.0f} s"


def fm(v) -> str:
    return "–" if v is None else f"{v:,.0f} MB"


def med(xs):
    return statistics.median(xs) if xs else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--atg", default="v1.5")
    ap.add_argument("--with-zap", action="store_true",
                    help="also show OWASP ZAP's time and resources from bench/oss_eval.py --zap-usage (not run by BENCH)")
    ap.add_argument("--before", default=None, help="an older ATG tag to compare with, e.g. v1.4")
    a = ap.parse_args()
    runs = load(a.atg)
    before = load(a.before)["atg"] if a.before and (OUT / f"atg-{a.before}").exists() else {}
    order = ["atg"] + TOOLS
    T = {t: tally(t, runs) for t in order}
    zap = zap_runs() if a.with_zap else {}
    md = [f"# ATG and eight free tools on ten open-source systems (ATG {a.atg})", "",
          "Produced by `bench/compare_tools.py` from the saved runs in `results/opensource/`. Every tool is scored "
          "against the same ground truth (`opensource/<id>/ground-truth.json`): a label counts as found when the "
          "tool reports the same weakness category on the same service or endpoint. Method and limits: "
          "`docs/BENCHMARK_OSS.md`. The sections follow the five questions of the evaluation: speed, computing "
          "resources, accuracy, systems covered and language limits.", ""]

    # ---- the tools: how each works (from each tool's own description in the installed package or its --help)
    md += ["## The tools compared", "",
           "How each tool works, in its own words where it describes itself (the package description or `--help` of "
           "the version installed by `bench/tools.Dockerfile` and `bench/tools_fetch.py`), with what it is good at and "
           "what it cannot see in this benchmark.", "",
           "| Tool (version, maker) | Kind | What it reads | How it works | Checks in this version | Good at | Cannot see |",
           "|---|---|---|---|---|---|---|",
           "| **ATG** (this project) | design review of a running test deployment | traffic through its sidecar, traces, "
           "the services' API documents, Kubernetes, Docker Compose and gateway files | merges the four sources into one "
           "API inventory, applies 27 rules, builds a threat graph and ranks attack paths | 27 rules | API behaviour "
           "and inventory, works for any language and both deployment formats | source code; container hardening "
           "and service-account checks (no rule); anything not in HTTP traffic |",
           "| Checkov 3.4.5 (Bridgecrew) | infrastructure-as-code scanner (\"Infrastructure as code static analysis\") "
           "| Kubernetes files, secrets in files, API documents; also Terraform, Helm, Dockerfiles and more | evaluates "
           "each policy on every resource of the parsed files (\"graph-based scanning\") | 119 Kubernetes checks, 18 "
           "secret detectors, 21 OpenAPI checks | many file formats, secrets | Docker Compose; the running API; it "
           "needs up to about 1 GB of memory |",
           "| Kubescape 3.0.18 (ARMO) | Kubernetes posture scanner (\"a tool for testing Kubernetes security "
           "posture\") | Kubernetes YAML files or a live cluster | evaluates controls from its control library on each "
           "resource | 290 controls in the downloaded library | broad Kubernetes controls (RBAC, hardening, network "
           "policy) | Docker Compose; workloads with removed API versions (it skipped FTGO's) |",
           "| kube-linter 0.7.1 (StackRox) | Kubernetes linter (\"Lint Kubernetes YAML files and Helm charts\") | "
           "Kubernetes YAML files | runs each built-in check on every object | 57 built-in checks | fastest and "
           "smallest | Docker Compose; fewer checks |",
           "| Polaris 9.6.1 (Fairwinds) | Kubernetes best-practice checker (\"Validation of best practices in your "
           "Kubernetes clusters\") | Kubernetes YAML files (audit mode) or a cluster | checks each workload and its "
           "containers against its policy | 32 checks run by default | most precise of all | Docker Compose |",
           "| Spectral 6.17.1 + OWASP ruleset 2.0.1 (Stoplight) | API document linter | OpenAPI documents | runs rules "
           "on the JSON or YAML of the document; the OWASP ruleset follows the OWASP API Security Top 10 2023 | 28 "
           "OWASP rules | missing security schemes, error responses, rate-limit responses in the document | anything "
           "not written in a document: in its own words, \"As OpenAPI is only describing the surface level of the API "
           "it cannot see what is happening in your code\"; 7 systems have no document |",
           "| Bandit 1.9.4 (PyCQA) | Python code scanner (\"Security oriented static analyser for python code\") | "
           "Python source | \"processes each file, builds an AST from it, and runs appropriate plugins against the AST "
           "nodes\" | 75 tests | code mistakes such as hard-coded passwords or requests without a timeout | other "
           "languages; deployment and API design |",
           "| gosec 2.21.4 (securego) | Go code scanner (\"analyzes Go source code to look for common programming "
           "mistakes that can lead to security problems\") | Go source | loads each Go package and runs its rules | "
           "41 rules | Go code mistakes such as unchecked errors or weak random numbers | other languages; it must "
           "load the packages, so it is the slowest on large Go systems |",
           "| njsscan 1.0.1 (Ajin Abraham) | Node.js code scanner (\"a SAST tool that can find insecure code patterns "
           "in your Node.js applications\") | Node.js source | pattern matching with libsast and semgrep | 124 rules "
           "| insecure Node.js code patterns | other languages |",
           ] + (["| OWASP ZAP 2.16.1 | active scanner (DAST) | the running application over HTTP | finds pages with its "
           "spider and in API documents, then sends attack requests and reads the responses | its default active-scan "
           "policy | injection, missing security headers, information in responses | deployment files, design, "
           "service-to-service calls; operations it cannot find |"] if zap else []) + [""]

    # ---- 1. Speed
    md += ["## 1. Speed", "", "### Time to review one system", "",
           "Slowest first.", "",
           "| Tool | Systems it can read | Median | Fastest | Slowest |", "|---|---:|---:|---:|---:|"]
    speed = [("**ATG** (Phases 1-4)" if t == "atg" else NAMES[t], T[t]["ran"], T[t]["secs"]) for t in order]
    walls = [r["scan_wall_s"] for r in runs["atg"].values() if r.get("scan_wall_s")]
    if walls:
        speed.append(("**ATG**, whole scan (with the wait for the capture buffers)", len(walls), walls))
    if zap:
        speed.append(("OWASP ZAP (spider and active scan, as an outside tester)", len(zap), [z["seconds"] for z in zap.values()]))
    for name, ran, xs in sorted(speed, key=lambda r: -(med(r[2]) or 0)):
        md.append(f"| {name} | {ran}/10 | {fs(med(xs))} | {fs(min(xs, default=None))} | {fs(max(xs, default=None))} |")
    md += ["", "ATG's time is Phases 1-4 of one scan (reading all four sources, normalising, analysing and writing "
           "the pages), measured inside the ATG container; it does not include starting the system or its users. "
           "The whole scan adds the wait until the sidecar and the Collector are quiet. The other tools' time is one "
           "run of the tool on the system's files (the first run of each tool is slower: it loads its rules). "
           + ("ZAP's time was measured on the 2-vCPU test host by `bench/oss_eval.py --zap-usage`." if zap else ""), ""]

    # ---- 2. Computing resources
    def fmb(v):
        return "–" if v is None else f"{v:,.0f} MB" if v >= 10 else f"{v:.1f} MB" if v >= 1 else f"{v * 1024:.0f} KB"

    def fc(v):
        return "–" if v is None else f"{v:.2f}"

    def rescells(lists: dict) -> str:
        m = {k: med(v) for k, v in lists.items()}
        return (f"{fs(m['cpu_s'])} | {fs(m['user_s'])} / {fs(m['sys_s'])} | {fc(m['cores'])} | {fm(m['peak_mb'])} | "
                f"{fm(m['avg_mb'])} | {fmb(m['read_mb'])} | {fmb(m['write_mb'])} | "
                f"{'–' if m['processes'] is None else int(round(m['processes']))}")
    md += ["## 2. Computing resources", "",
           "How much of the computer each tool uses to review one system. CPU time is the processor time all of the "
           "tool's processes used (user time: running the tool's own code; system time: the operating system "
           "working for it, such as reading files). *Cores used* is CPU time divided by the time the run took: 1.00 "
           "means one processor core busy for the whole run. Memory is the resident memory of all its processes, at "
           "its highest and on average over the run. Data read and written counts the bytes its processes read and "
           "wrote (files, pipes and network sockets alike), so it shows how much input the tool goes through. "
           "Processes counts the processes it started.", "",
           "### Computing resources to review one system", "",
           "Median over the systems each tool can read; most CPU time first.", "",
           "| Tool | Systems it can read | CPU time | User / system | Cores used | Memory at peak | Memory on average | "
           "Data read | Data written | Processes |",
           "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    resrows = [("**ATG** scan (ATG + PostgreSQL containers)" if t == "atg" else NAMES[t], T[t]["ran"], T[t]["res"]) for t in order]
    if zap:
        resrows.append(("OWASP ZAP (outside tester)", len(zap),
                        {k: [z[k] for z in zap.values() if z.get(k) is not None] for k in RES_KEYS}))
    for name, ran, lists in sorted(resrows, key=lambda r: -(med(r[2]["cpu_s"]) or 0)):
        md.append(f"| {name} | {ran}/10 | " + rescells(lists) + " |")
    md += ["", "### The largest use on one system", "", "Most CPU time first.", "",
           "| Tool | CPU time (most) | Memory at peak (most) | On which system |", "|---|---:|---:|---|"]
    most = []
    for t in order:
        rs = [(sid, r) for sid, r in runs[t].items() if r.get("applicable") and r.get("cpu_s") is not None]
        if rs:
            sid, r = max(rs, key=lambda x: x[1]["cpu_s"])
            most.append(("**ATG** scan" if t == "atg" else NAMES[t], r["cpu_s"], max(r2.get("peak_mb") or 0 for _, r2 in rs), sid))
    if zap:
        sid, z = max(zap.items(), key=lambda x: x[1]["cpu_s"])
        most.append(("OWASP ZAP", z["cpu_s"], max(v["peak_mb"] for v in zap.values()), sid))
    for name, c, m, sid in sorted(most, key=lambda r: -r[1]):
        md.append(f"| {name} | {fs(c)} | {fm(m)} | {sid} (most CPU) |")
    md += ["", "How it was measured: for the eight tools, `bench/run_tools.py` runs each tool as a child process; CPU "
           "time comes from `wait4`, memory and the read/write byte counters from `/proc`, sampled every 20 ms. For ATG, "
           "`bench/usage.py` reads Docker's counters for the ATG and PostgreSQL containers during the scan (CPU time "
           "exactly, memory every 0.5 s, the in-memory folders included); data read and written are the scan process's "
           "own counters (`/proc/self/io`). The first run of each tool is slower (it loads its rules). "
           + ("For ZAP, `bench/oss_eval.py --zap-usage` restarts ZAP for every system and reads its process tree from "
              "`/proc`; ZAP was measured on the 2-vCPU test host." if zap else ""), ""]
    us = {sid: r["usage"] for sid, r in runs["atg"].items() if r.get("usage")}
    if us:
        roles = [("atg-proxy", "sidecar (mitmproxy): carries and records the traffic"),
                 ("atg-collector", "OpenTelemetry Collector: receives the spans"),
                 ("atg-postgres", "PostgreSQL: EUJF records, threat graph, attack-path query"),
                 ("atg", "ATG: scan (Phases 1-4), pages, web view")]

        def col(stage, what, name):
            return [u["stages"].get(stage, {}).get(what, {}).get(name, 0) for u in us.values()]
        md += ["### What ATG's four containers use during a review", "",
               f"Median over the {len(us)} systems (most in brackets). *While users run*: the system's users send their "
               "requests through the sidecar; *scan*: Phases 1-4. Network: megabytes the container received and sent "
               "during the whole review (the sidecar's traffic counts twice: in from a caller, out to the service, and "
               "back). Disk: ATG keeps its data in memory, so its containers read and write almost nothing on disk.", "",
               "| Container | Role | CPU while users run | CPU during the scan | Memory at peak | Memory on average | "
               "Network in / out | Disk read / write | Processes |", "|---|---|---:|---:|---:|---:|---:|---:|---:|"]

        def stage_sum(u, key, name):
            return sum((u["stages"].get(st, {}).get(key) or {}).get(name, 0) for st in ("users", "scan"))
        for name, role in roles:
            cu, cs = col("users", "cpu_s", name), col("scan", "cpu_s", name)
            mem = [max(a_, b_) for a_, b_ in zip(col("users", "mem_peak_mb", name), col("scan", "mem_peak_mb", name))]
            avg = [v for v in col("users", "mem_avg_mb", name) if v] or [0]
            nin = [stage_sum(u, "net_in_mb", name) for u in us.values()]
            nout = [stage_sum(u, "net_out_mb", name) for u in us.values()]
            dr = [stage_sum(u, "disk_read_mb", name) for u in us.values()]
            dw = [stage_sum(u, "disk_write_mb", name) for u in us.values()]
            pids = [max(col("users", "pids_peak", name)[i], col("scan", "pids_peak", name)[i]) for i in range(len(us))]
            md.append(f"| {name} | {role} | {fs(med(cu))} ({fs(max(cu))}) | {fs(med(cs))} ({fs(max(cs))}) | "
                      f"{fm(med(mem))} ({fm(max(mem))}) | {fm(med(avg))} | {fmb(med(nin))} / {fmb(med(nout))} | "
                      f"{fmb(med(dr))} / {fmb(med(dw))} | {int(med(pids) or 0)} |")
        tot = [max(u["stages"].get(st, {}).get("mem_peak_total_mb", 0) for st in ("users", "scan")) for u in us.values()]
        allcpu = [sum(sum((u["stages"].get(st, {}).get("cpu_s") or {}).values()) for st in ("users", "scan")) for u in us.values()]
        md.append(f"| **All four** | | {fs(med(allcpu))} ({fs(max(allcpu))}) in all | | {fm(med(tot))} ({fm(max(tot))}) | | | | |")
        per_req = [1000 * u["stages"]["users"]["cpu_s"].get("atg-proxy", 0) / runs["atg"][sid]["flows"]
                   for sid, u in us.items() if runs["atg"][sid].get("flows") and "users" in u["stages"]]
        if per_req:
            md += ["", f"The sidecar used {med(per_req):.1f} ms of CPU per request it carried (median; "
                   f"{min(per_req):.1f}-{max(per_req):.1f} ms)."]
        md.append("")

    # ---- 3. Accuracy
    TOT = T["atg"]["labels"]
    GS = {g: v[0] for g, v in T["atg"]["groups"].items()}
    md += ["## 3. Accuracy: known weaknesses found", "",
           f"The {TOT} known weaknesses fall into three groups:", "",
           f"- **Configuration ({GS['Configuration']})**: mistakes in the deployment files (Kubernetes manifests, Docker Compose files, "
           "gateway settings), for example a container that may run as root, no network policy, no memory or CPU "
           "limit, a password written in a plain file, an image without a fixed version, or a public entry without "
           "HTTPS. The Kubernetes scanners and ATG can find these.",
           f"- **API behaviour ({GS['API behaviour']})**: how the running API behaves when it is used, for example an operation that "
           "returns private data without a login, one service calling another without credentials, an admin or "
           "debug page open to everyone, a password sent in the URL, or a login with no limit on wrong tries. Only "
           "a tool that sees the API in use (ATG) or reads its API document (Spectral and Checkov's OpenAPI checks, partly) can find these.",
           f"- **Inventory and visibility ({GS['Inventory and visibility']})**: what the company does not know about its own APIs, for example "
           "operations that no API document describes (shadow APIs) and services that send no traces. Only ATG "
           "compares what runs with what is documented.", "",
           "### Inventory and visibility: detected or not", "",
           "Finding these needs the running system compared with the API documents and the deployment files, so it "
           "is a capability a tool either has or does not have; it is shown as *detected* or *not detected* rather "
           "than as a score, and left out of the chart above.", "",
           "| Tool | Shadow APIs and services without an API document | Services that send no traces | "
           f"Inventory and visibility ({GS['Inventory and visibility']}) |", "|---|---|---|---|"]
    o_tot = {c: sum(1 for sid in SYSTEMS for l in labels(sid) if l[0] == c) for c in ("O1", "O2")}
    for t in order:
        x = T[t]
        o = {c: (x["cats"].get(c) or [0, 0])[1] for c in ("O1", "O2")}

        def det(n, tot):
            return f"Detected ({n}/{tot})" if n else "Not detected"
        g = x["groups"]["Inventory and visibility"]
        md.append(f"| {'**ATG**' if t == 'atg' else NAMES[t]} | {det(o['O1'], o_tot['O1'])} | {det(o['O2'], o_tot['O2'])} | "
                  f"{'**' + det(g[1], g[0]) + '**' if g[1] else det(g[1], g[0])} |")
    ops = atg_operations(runs)
    if ops:
        to = [sum(v[i] for v in ops.values()) for i in range(3)]
        md += ["", "### Operations ATG listed (its API inventory)", "",
               "Every API operation in the systems' code, against ATG's inventory from the same DEMO-ALL run. *Correct* is "
               "the share of ATG's entries that are real operations (an operation listed twice, for example once at the "
               "gateway and once at the service, counts as one wrong entry). No other tool lists operations.", "",
               "| System | Operations in the code | ATG listed correctly | ATG's entries | Correct |", "|---|---:|---:|---:|---:|"]
        for sid in sorted(ops, key=lambda x: -ops[x][0]):
            v = ops[sid]
            md.append(f"| {sid} | {v[0]} | {v[1]} ({pct(v[1], v[0])}) | {v[2]} | {pct(v[1], v[2])} |")
        md.append(f"| **All** | {to[0]} | {to[1]} ({pct(to[1], to[0])}) | {to[2]} | {pct(to[1], to[2])} |")
    md += ["", "### How many known weaknesses each tool found", "",
           f"*Found* counts all {TOT} known weaknesses of the ten systems, so a tool that cannot read a system scores 0 "
           "there. *Found, of what it can check* counts only the kinds of weakness the tool has a check for, on the "
           "systems it can read. *Correct reports* is the share of the tool's reports (kind of weakness and place) "
           "that are in the answer key; the rest are false alarms or problems the key does not list. Inventory and "
           "visibility is in the table above.", "",
           f"| Tool | Systems it can read | Found (of {TOT}) | " + " | ".join(g for g in sc.GROUPS if not g.startswith("Inventory"))
           + " | Found, of what it can check | Correct reports |",
           "|---|---:|---:|" + "---:|" * (len(sc.GROUPS) - 1) + "---:|---:|"]
    for t in order:
        x = T[t]
        groups = " | ".join(f"{v[1]}/{v[0]} ({pct(v[1], v[0])})" for k, v in x["groups"].items() if not k.startswith("Inventory"))
        md.append(f"| {'**ATG**' if t == 'atg' else NAMES[t]} | {x['ran']}/10 | {x['found']}/{x['labels']} ({pct(x['found'], x['labels'])}) | "
                  f"{groups} | {x['in_reach_found']}/{x['in_reach']} ({pct(x['in_reach_found'], x['in_reach'])}) | "
                  f"{x['confirmed']}/{x['reported']} ({pct(x['confirmed'], x['reported'])}) |")
    md.append("")
    un, lvl = Counter(), Counter()
    for sid, r in runs["atg"].items():
        for cat, tgt in sc.score(sid, r["pairs"])["unconfirmed"]:
            un[cat] += 1
            lvl[(cat, tgt.split(":")[0])] += 1
    if un:
        def inv(c, what):
            return (f"{lvl[(c, 'svc')]} on workloads the answer key does not count as API services (databases, caches, "
                    f"message brokers, registries, monitoring, load generators, web front ends); {lvl[(c, 'ep')]} on "
                    f"operations, mostly the extra entries ATG lists at Acme Air's Ingress controller and at FTGO's "
                    f"gateway ({what})")
        why = {"O1": inv("O1", "no API document"), "O2": inv("O2", "no traces"),
               "A1": "operations with no authentication check that the answer key does not count as sensitive; most "
                     "serve public data, such as a catalogue or a flight search"}
        md += ["### ATG's reports that are not in the answer key", "",
               f"{sum(un.values())} of ATG's {T['atg']['reported']} reports match no known weakness. By kind:", "",
               "| Kind | Reports | Note |", "|---|---:|---|"]
        for c, n in un.most_common():
            md.append(f"| {c} {sc.CAT_NAMES[c]} | {n} | {why.get(c, '')} |")
        md.append("")

    # ---- why the file scanners find configuration but no API behaviour or inventory: every check they reported
    md += ["### Why the file scanners find configuration but no API behaviour or inventory", "",
           "API behaviour is how the running API answers: who may call an operation, what it returns, whether one "
           "service calls another without credentials. Kubernetes and Compose files do not describe API operations at "
           "all, and code scanners look for coding mistakes, not for who may call what. Only an API document says "
           "something about the API, which is why Spectral (and Checkov's OpenAPI checks) find a few API-behaviour "
           "weaknesses where a document exists. Inventory and visibility compare what runs with what is documented "
           "and traced; a tool that reads one kind of file has nothing to compare it with.", "",
           "To check that this is not a scoring gap, every check each tool reported on the ten systems is listed "
           "below: *counted* checks are translated into a kind of known weakness, the others are not about any of "
           "the 22 kinds (most are about probes, labels, namespaces, requests or image signatures).", "",
           "| Tool | Checks it reported | Findings | Counted (checks / findings) | Not counted: the most frequent |",
           "|---|---:|---:|---:|---|"]
    for t in TOOLS:
        raw, names = {}, {}
        for sid in SYSTEMS:
            r = runs[t].get(sid) or {}
            for k, v in (r.get("raw") or {}).items():
                raw[k] = raw.get(k, 0) + v
            names.update(r.get("names") or {})
        counted = {k for k in raw if k in COUNTED.get(t, set()) or COUNTED_RE.get(t, lambda _k: False)(k)}
        rest = sorted((k for k in raw if k not in counted), key=lambda k: -raw[k])
        top = "; ".join(f"{k} {('(' + names[k][:60] + ')') if names.get(k) and names[k] != k else ''} x{raw[k]}".replace("  ", " ")
                        for k in rest[:6])
        md.append(f"| {NAMES[t]} | {len(raw)} | {sum(raw.values())} | {len(counted)} / {sum(raw[k] for k in counted)} | "
                  f"{top or '–'} |")
    md += ["", "Corrections made by this check (version 1.6.4): Polaris's `sensitiveContainerEnvVar` and "
           "`sensitiveConfigmapContent` now count as secrets in deployment files and `tlsSettingsMissing` as an entry "
           "without TLS (they had been left out); Spectral's error-response rules no longer count as \"no TLS\" (only "
           "its http:// server rule does); and Checkov now also reads the API documents with its OpenAPI checks.", ""]

    # ---- Table B: by category
    cats = sorted(T["atg"]["cats"], key=lambda c: (c[0], int(c[1:])))
    md += ["### Found, by kind of weakness", "",
           "| Code | Kind of weakness | Known | " + " | ".join(NAMES[t] for t in order) + " |",
           "|---|---|---:|" + "---:|" * len(order)]
    for c in cats:
        n = T["atg"]["cats"][c][0]
        cells = []
        for t in order:
            scope = ATG_SCOPE if t == "atg" else SCOPE.get(t, set())
            cells.append(str(T[t]["cats"].get(c, [0, 0])[1]) if c in scope else "·")
        md.append(f"| {c} | {sc.CAT_NAMES[c]} | {n} | " + " | ".join(cells) + " |")
    md += ["", "· = the tool has no check for this category. ATG reports missing resource limits (C3) only for "
           "services reachable from the internet, where they matter for API4 (resource consumption); the scanners "
           "report every container, which is why they find more C3 labels.", ""]

    # ---- Table C: per system, configuration labels
    src = {}
    for sid in SYSTEMS:
        for l in json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))["labels"]:
            src[l.get("source")] = src.get(l.get("source"), 0) + 1
    N_CODE, N_RULE = src.get("code review", 0), sum(v for k, v in src.items() if k != "code review")
    md += ["### Found on each system", "",
           "**Where the known weaknesses come from.** Every system has an answer key, "
           "`opensource/<system>/ground-truth.json`, made before any tool was scored. Each known weakness is one "
           "kind of weakness (22 kinds, codes A1-A10, C1-C10, O1-O2) at one place (a service or an API operation), "
           "and it says where it comes from:", "",
           f"- {N_CODE} come from reading the system's code (marked *code review*), each with the file it was found in. "
           "Example: Bank of Anthos's login form has no limit on wrong tries (`src/frontend/frontend.py`).",
           f"- {N_RULE} come from fixed rules applied to the system's real deployment files, its service calls and its API "
           "documents (marked *deployment files*; `opensource/config_labels.py`). Example: every container that "
           "does not set `runAsNonRoot` gets \"may run as root\"; every service that no NetworkPolicy selects gets "
           "\"no network segmentation\".", "",
           "**How a tool gets credit.** Each tool's findings are translated into the same 22 kinds with a fixed table "
           "(`bench/run_tools.py` for the tools, `bench/oss_scoring.py` for ATG). Example: Checkov's `CKV_K8S_23` "
           "and ATG's `API8-ROOT` both become \"may run as root\". A known weakness counts as found when the tool "
           "reports the same kind at the same service or operation. One script marks every tool the same way; n/a "
           "means the tool cannot read that system's files, and 0 that it ran and found none.", "",
           "<!--FIG:systems-->", "",
           "The same numbers as a table, the systems with the most known weaknesses first:", "",
           "| System | Known weaknesses | " + " | ".join(f"**{NAMES[t]}**" if t == "atg" else NAMES[t] for t in order) + " |",
           "|---|---:|" + "---:|" * len(order)]
    for sid in sorted(SYSTEMS, key=lambda x: -len(labels(x))):
        lab = labels(sid)
        cells = []
        for t in order:
            r = runs[t].get(sid)
            if not r or not r.get("applicable"):
                cells.append("n/a")
            else:
                n = len(found_set(sid, r["pairs"]))
                cells.append(f"**{n}**" if t == "atg" else str(n))
        md.append(f"| {sid} | {len(lab)} | " + " | ".join(cells) + " |")
    md.append("")

    # ---- Table E: ATG plus a Kubernetes scanner
    md += ["### ATG and a Kubernetes scanner used together", "",
           "Known weaknesses found by each tool, by both, and by at least one of them. The scanners add the container-hardening checks "
           "ATG does not have (C9, C10); ATG adds the API, inventory and Compose findings they cannot make.", "",
           "| Pair | ATG | Other tool | Both | At least one |", "|---|---:|---:|---:|---:|"]
    for t in ("polaris", "kubescape", "checkov"):
        A = B = U = I = 0
        for sid in SYSTEMS:
            fa = found_set(sid, runs["atg"][sid]["pairs"]) if sid in runs["atg"] else set()
            r = runs[t].get(sid)
            fb = found_set(sid, r["pairs"]) if r and r.get("applicable") else set()
            A, B, U, I = A + len(fa), B + len(fb), U + len(fa | fb), I + len(fa & fb)
        tl = sum(len(labels(sid)) for sid in SYSTEMS)
        md.append(f"| ATG + {NAMES[t]} | {A} | {B} | {I} | {U}/{tl} ({pct(U, tl)}) |")
    md.append("")
    md += future_plan(runs)

    # ---- Table D: where tools stop
    md += ["## 4. Systems covered", "", "### Which systems each tool can read", "",
           "| Tool | What it needs | Systems it could not read |", "|---|---|---|"]
    needs = {"atg": "a running test deployment (many languages), plus whatever files exist",
             "checkov": "Kubernetes manifests", "kubescape": "Kubernetes manifests (current API versions)",
             "kube-linter": "Kubernetes manifests", "polaris": "Kubernetes manifests",
             "spectral": "an OpenAPI document", "bandit": "Python source", "gosec": "Go source", "njsscan": "Node.js source"}
    for t in order:
        na = T[t]["na"]
        why = sorted(set(na.values()))
        md.append(f"| {NAMES[t]} | {needs[t]} | {len(na)}: {', '.join(na) or 'none'}" + (f" ({'; '.join(why)})" if why else "") + " |")
    md += ["", "Kubescape also ran on FTGO but found 6 of 82 labels: FTGO declares its Deployments and StatefulSets "
           "with API versions Kubernetes has removed (`extensions/v1beta1`, `apps/v1beta1`), and Kubescape skipped "
           "them, scanning only the Services, the Secret and the Job. The other scanners read them.", "",
           "## 5. Language limits", "",
           "The three code scanners each read one programming language. The Kubernetes scanners and Spectral do not "
           "read code: their limit is the kind of file (Kubernetes files, API documents), so they reach only the "
           "services, of whatever language, that have such a file. ATG does not read source code either: it reviews "
           "the running system (its HTTP traffic and traces) and its files, so it reviewed the services of all eight "
           "languages in the ten systems. Its limits are of another kind (the last table).", "",
           "### Services and languages each tool can review", "",
           "| Tool | What it reads | Services it can review (of 65) | Languages (of 8) | Which languages |",
           "|---|---|---:|---:|---|"]
    reach = tool_reach(runs)
    all_langs = sorted({l for rows in service_languages().values() for _, l in rows})
    for t in ["atg"] + TOOLS:
        ls = sorted({l for _, _, l in reach[t]}, key=lambda l: all_langs.index(l))
        md.append(f"| {'**ATG**' if t == 'atg' else NAMES[t]} | {TOOL_READS[t]} | {len(reach[t])} | {len(ls)} | {', '.join(ls)} |")
    langs = service_languages()
    md += ["", "### The services of each system and their languages", "",
           "| System | Services | Languages | Each service (language) | Bandit (Python) | gosec (Go) | njsscan (Node.js) |",
           "|---|---:|---|---|---:|---:|---:|"]
    tot = [0, 0, 0, 0]
    for sid in SYSTEMS:
        rows = langs[sid]
        n = len(rows)
        cov = [sum(1 for _, l in rows if LANG_SCANNER.get(l, "").lower() == t) for t in ("bandit", "gosec", "njsscan")]
        tot = [tot[0] + n] + [tot[i + 1] + cov[i] for i in range(3)]
        used = sorted({l for _, l in rows}, key=lambda l: [l2 for _, l2 in rows].index(l))
        md.append(f"| {sid} | {n} | {', '.join(used)} | " + ", ".join(f"{name} ({l})" for name, l in rows) + " | "
                  + " | ".join(str(c) for c in cov) + " |")
    md.append(f"| **All** | {tot[0]} | {len(all_langs)} languages | | " + " | ".join(f"{c} ({pct(c, tot[0])})" for c in tot[1:]) + " |")
    md += ["", f"Together the three code scanners read {sum(tot[1:])} of {tot[0]} services "
           f"({pct(sum(tot[1:]), tot[0])}); the Java, C#, Ruby, PHP and browser JavaScript services have no free "
           "code scanner here.", ""]
    by_lang = {}
    for rows in langs.values():
        for _, lang in rows:
            by_lang[lang] = by_lang.get(lang, 0) + 1
    md += ["### Which tool can review each language", "",
           "yes: the tool reviewed at least one service of this language in the ten systems.", "",
           "| Language | Services | " + " | ".join(NAMES[t] for t in ["atg"] + TOOLS) + " |",
           "|---|---:|" + ":---:|" * (len(TOOLS) + 1)]
    for lang, n in sorted(by_lang.items(), key=lambda x: -x[1]):
        cells = ["yes" if any(l == lang for _, _, l in reach[t]) else "no" for t in ["atg"] + TOOLS]
        md.append(f"| {lang} | {n} | " + " | ".join(cells) + " |")
    md += ["", "### What ATG cannot read", "",
           "| What | Where in the ten systems | Why |", "|---|---|---|",
           "| Source code, in any language | all 65 services | ATG reviews the running system and its files, not the "
           "code, so code bugs such as injection need a code scanner or an active scanner |",
           "| Messages on a queue | RabbitMQ in Robot Shop and PiggyMetrics, Kafka in FTGO | the sidecar records HTTP "
           "traffic only; Robot Shop's dispatch service, which only reads RabbitMQ, has no API to see |",
           "| Database traffic | MongoDB, MySQL, PostgreSQL, Redis or Memcached in eight systems | not HTTP; ATG only "
           "lists which services connect to a database, from their settings |",
           "| Operations nobody uses during the review | operations outside the users' session | the traffic and "
           "traces show only what is used; API documents and deployment files show the rest only if they list it |", ""]

    # ---- Table F: ATG before and after the version 1.5 fixes
    if before:
        now = "this run" if a.atg == "laptop" else a.atg
        md += ["## 6. ATG before and after its rule fixes", "", f"### ATG {a.before} against {now} on the same systems", "",
               "Versions 1.5 and 1.6 were made after reading the misses of version 1.4 on these systems (see "
               "`docs/BENCHMARK_OSS.md`), so this table shows the fixes worked, not how ATG does on unseen systems.", "",
               "| System | Known weaknesses | Found " + a.before + " | Found " + now + " | Correct reports " + a.before + " | Correct reports " + now + " |",
               "|---|---:|---:|---:|---:|---:|"]
        tb = tally_runs = {"before": [0, 0, 0], "after": [0, 0, 0]}
        for sid in SYSTEMS:
            if sid not in before or sid not in runs["atg"]:
                continue
            lab = labels(sid)
            sb = sc.score(sid, before[sid]["pairs"])
            sa = sc.score(sid, runs["atg"][sid]["pairs"])
            md.append(f"| {sid} | {len(lab)} | {sb['found']} | {sa['found']} | {pct(sb['confirmed'], sb['reported'])} | "
                      f"{pct(sa['confirmed'], sa['reported'])} |")
            for k, s in (("before", sb), ("after", sa)):
                tb[k][0] += s["found"]
                tb[k][1] += s["confirmed"]
                tb[k][2] += s["reported"]
        tl = sum(len(labels(s)) for s in SYSTEMS if s in before and s in runs["atg"])
        md.append(f"| **All** | {tl} | {tb['before'][0]} ({pct(tb['before'][0], tl)}) | {tb['after'][0]} ({pct(tb['after'][0], tl)}) | "
                  f"{pct(tb['before'][1], tb['before'][2])} | {pct(tb['after'][1], tb['after'][2])} |")
        md.append("")

    (OUT / "comparison.md").write_text("\n".join(md), encoding="utf-8")
    js = {t: {k: v for k, v in T[t].items() if k not in ("secs", "cpu", "mem")}
          | {"median_s": med(T[t]["secs"]), "median_cpu_s": med(T[t]["cpu"]), "median_peak_mb": med(T[t]["mem"]),
             "max_cpu_s": max(T[t]["cpu"], default=None), "max_peak_mb": max(T[t]["mem"], default=None)}
          for t in order}
    if zap:
        js["zap"] = {"ran": len(zap), "median_s": med([z["seconds"] for z in zap.values()]),
                     "median_cpu_s": med([z["cpu_s"] for z in zap.values()]),
                     "median_peak_mb": med([z["peak_mb"] for z in zap.values()]),
                     "max_cpu_s": max(z["cpu_s"] for z in zap.values()), "max_peak_mb": max(z["peak_mb"] for z in zap.values())}
    (OUT / "comparison.json").write_text(json.dumps(js, indent=1), encoding="utf-8")
    print(f"wrote {(OUT / 'comparison.md').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
