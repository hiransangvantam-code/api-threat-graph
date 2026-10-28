"""
Pages of the ATG web view (output/site, served on http://localhost:8080), plus the
scan state shared by serve.py and scan.py.

  index.html                    status while waiting for traffic, then the results home page
  threat-graph-<scan>.html      the threat graph of one scan (Phase 3 output, drawn by Phase 4)
  dashboard-<scan>.html         the full Phase 4 dashboard of one scan
  phase1-report-<scan>.html     what each Phase 1 source found
  scans/<scan>/                 the files each phase wrote: raw/*.json (1), eujf.json (2), analysis.json (3)
  results/                      the Section IV experiment results that ship with the code
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
import yaml  # noqa: E402

from atg.dashboard import CSS as DASH_CSS, NAV_CSS, _graph_svg, build_dashboard  # noqa: E402
from extractor.report import CSS as BASE_CSS  # noqa: E402

OUT = ROOT / "output"
SITE = OUT / "site"
STATE = OUT / "scan-state.json"
CAPTURE = Path(os.environ.get("ATG_CAPTURE_DIR", "/data/capture"))      # written by the mitmproxy sidecar
TELEMETRY = Path(os.environ.get("ATG_TELEMETRY_DIR", "/data/telemetry"))  # written by the OTel Collector
TARGET_CFG = ROOT / "docker" / "extractor-target.yaml"
E = html.escape


# ---------------------------------------------------------------- scan state (shared by serve.py and scan.py)
def load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"offsets": {}, "store": os.environ.get("ATG_GRAPH_STORE"), "started": time.time(), "scanning": None}


def save_state(st: dict) -> None:
    write(STATE, json.dumps(st, indent=1))


def capture_files() -> list[Path]:
    return sorted([*CAPTURE.glob("*.jsonl"), *TELEMETRY.glob("*.jsonl")])


def new_lines(st: dict) -> dict:
    """How much the sidecar and the Collector wrote since the last scan."""
    def count(folder):
        n = 0
        for f in folder.glob("*.jsonl"):
            off = st["offsets"].get(str(f), 0)
            try:
                with f.open("rb") as fh:
                    fh.seek(off)
                    n += fh.read().count(b"\n")
            except OSError:
                pass
        return n
    return {"flows": count(CAPTURE), "span_batches": count(TELEMETRY)}


def _http_ok(url: str) -> bool:
    try:
        return httpx.get(url, timeout=1.5, trust_env=False).status_code < 500
    except httpx.HTTPError:
        return False


def _tcp_ok(host: str, port: int) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except OSError:
        return False


def health_checks(st: dict) -> dict:
    cfg = yaml.safe_load(TARGET_CFG.read_text(encoding="utf-8"))
    target = [(f"{t['service']} ({t['base_url'].split('//', 1)[-1]})", _http_ok(t["base_url"] + "/health"))
              for t in cfg["sources"]["openapi"]["live_targets"]]
    proxy = os.environ.get("ATG_PROXY_HOST", "atg-proxy")
    coll = os.environ.get("ATG_COLLECTOR_HOST", "atg-collector")
    pg = os.environ.get("ATG_PG_HOST", "atg-postgres")
    atg = [(f"mitmproxy sidecar ({proxy}:8080 inline, :8081 east-west)", _tcp_ok(proxy, 8080) and _tcp_ok(proxy, 8081)),
           (f"OpenTelemetry Collector ({coll}:4318 OTLP)", _http_ok(f"http://{coll}:13133/")),
           (f"PostgreSQL ({pg}:5432)", _tcp_ok(pg, 5432) if st.get("store") else None)]
    return {"target": target, "atg": atg, "captured": new_lines(st)}

PAGE_CSS = """
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,250px),1fr));gap:10px}
.card{display:grid;gap:4px;align-content:start;border:1px solid var(--line);border-radius:8px;background:var(--surface);
  padding:14px 16px;text-decoration:none;color:var(--fg)}
.wrap a.card{color:var(--fg)}
a.card:hover{border-color:var(--accent)}
.card b{font:700 15px var(--f-display)}
.card span{font-size:13px;color:var(--muted);line-height:1.45}
.card a{color:var(--accent)}
.hero{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:10px}
@media (max-width:760px){.hero{grid-template-columns:1fr}}
.hero .card.main{border:2px solid var(--accent);padding:20px 22px}
.hero .card.main b{font-size:24px}
.hero .card.main .go{font:600 14px var(--f-body);color:var(--accent)}
.gprev{border:1px solid var(--line);border-radius:6px;background:var(--surface);pointer-events:none;margin:6px 0 2px}
.gprev svg{display:block;width:100%;height:250px}
.nums{width:100%;border-collapse:collapse;font-size:13.5px}
.nums th,.nums td{padding:5px 8px;border-bottom:1px solid var(--line);text-align:right;font-variant-numeric:tabular-nums}
.nums th:first-child,.nums td:first-child{text-align:left}
.checks{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:10px}
.checks ul{list-style:none;margin:0;padding:0;display:grid;gap:6px}
.checks li{display:grid;grid-template-columns:22px minmax(0,1fr);gap:6px;font-size:14px}
.ic{font:700 14px var(--f-mono)} .ic.ok{color:var(--ok)} .ic.bad{color:var(--crit)} .ic.wait{color:var(--muted)}
pre.log{white-space:pre-wrap;max-height:420px;overflow:auto;font-size:12px}
code.cmd{font:12.5px var(--f-mono);background:var(--surface-2);padding:2px 6px;border-radius:4px;word-break:break-word}
.arch{border:1px solid var(--line);border-radius:8px;background:var(--surface);padding:8px}
.arch svg{display:block;width:100%;height:auto;font-family:var(--f-body)}
.arch .box{fill:none;stroke:var(--line);stroke-width:1.5}
.arch .tgt{stroke:var(--t-api,#2563eb)} .arch .atg{stroke:var(--accent)}
.arch .node{fill:var(--surface-2);stroke:var(--line)}
.arch text{fill:var(--fg);font-size:12px} .arch .t{font-weight:700;font-size:13px} .arch .m{fill:var(--muted);font-size:11px}
.arch .flow path{stroke:var(--muted);stroke-width:1.4;fill:none} .arch .flow .hot{stroke:var(--accent);stroke-width:2}
.arch .ahd{fill:var(--muted)}
.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px}
.figs figure{margin:0;border:1px solid var(--line);border-radius:8px;background:#fff;padding:10px}
.figs img{width:100%;height:auto;display:block}
.figs figcaption{font:12.5px var(--f-mono);color:#5a6675;margin-top:6px}
.md table{border-collapse:collapse;font-size:13px}
.md th,.md td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
.md th{background:var(--surface-2)}
"""

FONTS = ('<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
         '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=JetBrains+Mono:wght@400;600;700&family=Public+Sans:wght@400;600;700&display=swap">')


def page(title: str, body: str, refresh: int | None = None, dash_css: bool = False) -> str:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">' + meta
            + f"<title>{E(title)}</title>{FONTS}"
            f"<style>{DASH_CSS if dash_css else BASE_CSS}{NAV_CSS}{PAGE_CSS}</style></head><body>"
            f'<div class="wrap">{body}</div></body></html>')


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def slug(i: int, label: str) -> str:
    return f"{i}-" + (re.sub(r"[^a-z0-9]+", "-", (label or "scan").lower()).strip("-") or "scan")


# ---------------------------------------------------------------- the two-Docker picture
ARCH_SVG = """<svg viewBox="0 0 960 272" role="img" aria-label="Two Docker deployments: the company's system and the ATG platform attached to its network">
<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path class="ahd" d="M0 0L10 5L0 10z"/></marker></defs>
<rect class="box tgt" x="10" y="10" width="330" height="244" rx="10"/>
<text class="t" x="24" y="34">Company Docker (target system)</text>
<text class="m" x="24" y="52">ShopLite on network customer-net</text>
<rect class="node" x="24" y="66" width="130" height="28" rx="5"/><text x="34" y="85">customers</text>
<rect class="node" x="190" y="110" width="136" height="26" rx="5"/><text x="200" y="128">api-gateway</text>
<rect class="node" x="190" y="146" width="136" height="26" rx="5"/><text x="200" y="164">user-service</text>
<rect class="node" x="190" y="182" width="136" height="26" rx="5"/><text x="200" y="200">order-service</text>
<rect class="node" x="190" y="218" width="136" height="26" rx="5"/><text x="200" y="236">payment-service</text>
<rect class="node" x="24" y="182" width="130" height="62" rx="5"/><text x="34" y="202">k8s manifests,</text>
<text x="34" y="218">gateway routes,</text><text x="34" y="234">spec files</text>
<rect class="box atg" x="400" y="10" width="550" height="244" rx="10"/>
<text class="t" x="414" y="34">ATG Docker (our platform)</text>
<text class="m" x="414" y="52">joins customer-net; nothing leaves the company network</text>
<rect class="node" x="414" y="66" width="150" height="28" rx="5"/><text x="424" y="85">mitmproxy sidecar</text>
<rect class="node" x="414" y="126" width="150" height="28" rx="5"/><text x="424" y="145">OTel Collector</text>
<rect class="node" x="414" y="176" width="150" height="28" rx="5"/><text x="424" y="195">OpenAPI probe</text>
<rect class="node" x="414" y="216" width="150" height="28" rx="5"/><text x="424" y="235">config (read-only)</text>
<rect class="node" x="600" y="66" width="160" height="28" rx="5"/><text x="610" y="85">1 Extractor</text>
<rect class="node" x="600" y="110" width="160" height="28" rx="5"/><text x="610" y="129">2 Normalizer → EUJF</text>
<rect class="node" x="600" y="154" width="160" height="28" rx="5"/><text x="610" y="173">3 Analysis, threat graph</text>
<rect class="node" x="600" y="198" width="160" height="28" rx="5"/><text x="610" y="217">4 Dashboard (this page)</text>
<rect class="node" x="788" y="104" width="150" height="84" rx="5"/><text class="t" x="798" y="126">PostgreSQL</text>
<text class="m" x="798" y="146">atg_eujf: EUJF (2)</text><text class="m" x="798" y="162">atg_nodes, atg_edges:</text>
<text class="m" x="798" y="178">threat graph (3)</text>
<g class="flow">
<path class="hot" d="M154 80 H412" marker-end="url(#ah)"/>
<path class="hot" d="M414 90 C370 90 370 123 328 123" marker-end="url(#ah)"/>
<path d="M326 160 C372 160 372 140 412 140" marker-end="url(#ah)"/>
<path d="M414 190 C372 190 372 196 328 196" marker-end="url(#ah)"/>
<path d="M89 244 V264 H489 V246" marker-end="url(#ah)"/>
<path d="M564 80 H598" marker-end="url(#ah)"/>
<path d="M564 140 C584 140 582 88 598 86" marker-end="url(#ah)"/>
<path d="M564 190 C586 190 584 90 598 88"/>
<path d="M564 230 C588 230 586 92 598 90"/>
<path d="M680 94 V108" marker-end="url(#ah)"/><path d="M680 138 V152" marker-end="url(#ah)"/>
<path d="M680 182 V196" marker-end="url(#ah)"/>
<path d="M760 124 H786" marker-end="url(#ah)"/><path d="M760 168 H786" marker-end="url(#ah)"/>
</g></svg>"""
ARCH_NOTE = ("Customer traffic goes through the mitmproxy sidecar, and so do the services' calls to each other. "
             "The services send their spans to the OTel Collector over OTLP. The probe reads each service's OpenAPI "
             "document, and the company's manifests are mounted read-only.")


# ---------------------------------------------------------------- status page (no scan yet, or a scan running)
def status_page(checks: dict, note: str = "", scanning: str | None = None, failed: str | None = None,
                log_tail: str = "") -> None:
    def li(ok, text):
        ic, cls = ("✓", "ok") if ok is True else ("✗", "bad") if ok is False else ("·", "wait")
        return f'<li><span class="ic {cls}">{ic}</span><span>{text}</span></li>'
    tgt = "".join(li(ok, E(name)) for name, ok in checks.get("target", []))
    atg = "".join(li(ok, E(name)) for name, ok in checks.get("atg", []))
    cap = checks.get("captured", {})
    if failed:
        head = f"<h1>The scan stopped with an error</h1><p class='muted'>{E(failed)}</p>"
    elif scanning:
        head = (f"<h1>Scanning: {E(scanning)}</h1><p class='muted'>Phases 1-4 are running on the traffic and traces "
                "captured so far. This page refreshes by itself.</p>")
    else:
        head = ("<h1>Waiting for the target system's traffic</h1><p class='muted'>The ATG platform is attached to the "
                "company's network. As soon as customers use the shop and a scan runs, the threat graph appears here. "
                "The start script does both for you; this page refreshes by itself.</p>")
    body = f"""
<header class="head"><div class="eyebrow">API Threat Graph · two Docker deployments</div>{head}</header>
<section class="arch">{ARCH_SVG}<p class="muted" style="margin:6px 8px 2px;font-size:13px">{ARCH_NOTE}</p></section>
<section class="checks">
  <div class="card"><b>Company Docker (target)</b><ul>{tgt}</ul></div>
  <div class="card"><b>ATG Docker (ours)</b><ul>{atg}</ul>
  <span>Captured since start: {cap.get('flows', 0)} HTTP flows, {cap.get('span_batches', 0)} span batches</span></div>
</section>
{f'<section><h2>Last lines of the log</h2><pre class="log">{E(log_tail)}</pre></section>' if log_tail else ''}
<section><p class="muted">{note}</p></section>"""
    write(SITE / "index.html", page("API Threat Graph: status", body, refresh=None if failed else 3))


# ---------------------------------------------------------------- experiment results that ship with the code
def md_to_html(text: str) -> str:
    """Just enough Markdown for results/tables.md: headings, paragraphs, tables, `code`, **bold**."""
    def inline(s):
        s = E(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    out, para, rows = [], [], []

    def flush():
        if para:
            out.append(f"<p>{inline(' '.join(para))}</p>")
            para.clear()
        if rows:
            cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
            body = [c for c in cells[1:] if not all(re.fullmatch(r":?-+:?", x) for x in c)]
            out.append('<div class="scroll"><table><thead><tr>' + "".join(f"<th>{inline(c)}</th>" for c in cells[0])
                       + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in body)
                       + "</tbody></table></div>")
            rows.clear()
    for line in text.splitlines():
        if line.startswith("|"):
            if para:
                flush()
            rows.append(line)
            continue
        if rows:
            flush()
        m = re.match(r"(#{1,4}) (.*)", line)
        if m:
            flush()
            lvl = min(len(m.group(1)) + 1, 4)
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
        elif not line.strip():
            flush()
        else:
            para.append(line.strip())
    flush()
    return "\n".join(out)


def experiment_pages() -> list[tuple[str, str, str]]:
    cards = []
    res = SITE / "results"
    dash_src = ROOT / "results" / "dashboards"
    names = {"crapi-C2": ("crAPI (OWASP), threat dashboard", "79 endpoints. Gateway-only capture, 30% of services untraced (C2)."),
             "trainticket-C2": ("Train Ticket, threat dashboard", "45 services, 272 endpoints. Condition C2."),
             "shoplite-C2": ("ShopLite under C2", "The same demo system with gateway-only capture."),
             "crapi-C1": ("crAPI under C1", "Everything captured and traced."),
             "trainticket-C1": ("Train Ticket under C1", "Everything captured and traced.")}
    if dash_src.exists():
        shutil.copytree(dash_src, res / "dashboards", dirs_exist_ok=True)
        for stem, (title, text) in names.items():
            if (dash_src / f"{stem}.html").exists():
                cards.append((title, f"results/dashboards/{stem}.html", text))
    figs = ROOT / "results" / "figures"
    if figs.exists():
        shutil.copytree(figs, res / "figures", dirs_exist_ok=True)
        imgs = "".join(f'<figure><img src="figures/{p.name}" alt="{E(p.stem)}" loading="lazy"><figcaption>{E(p.name)}</figcaption></figure>'
                       for p in sorted(figs.glob("*.png")))
        write(res / "figures.html", page("Section IV figures", f"""
<header class="head"><div class="eyebrow">Section IV · experiment results</div><h1>Figures</h1>
<nav class="navlinks"><a href="../index.html">Home</a><a href="tables.html">Tables</a></nav></header>
<section class="figs">{imgs}</section>"""))
        cards.append(("Figures", "results/figures.html", "All result charts from the experiment, as PNG."))
    tables = ROOT / "results" / "tables.md"
    if tables.exists():
        write(res / "tables.html", page("Section IV tables", f"""
<header class="head"><div class="eyebrow">Section IV · experiment results</div>
<nav class="navlinks"><a href="../index.html">Home</a><a href="figures.html">Figures</a></nav></header>
<section class="md">{md_to_html(tables.read_text(encoding="utf-8"))}</section>"""))
        cards.append(("Tables 1-20", "results/tables.html", "Every number in Section IV, mean ± sd over 5 seeds."))
    return cards


# ---------------------------------------------------------------- results home page
def build_results(store_url: str | None, started: float) -> None:
    """Rebuild every page from the scans stored under output/runs and the graph store."""
    from atg.graphstore import GraphStore

    runs = sorted(p for p in (OUT / "runs").iterdir() if p.is_dir() and (p / "analysis.json").exists())
    if not runs:
        return
    store = GraphStore(store_url or f"sqlite:///{OUT / 'atg.db'}")
    scans = []
    for i, rd in enumerate(runs, 1):
        analysis = json.loads((rd / "analysis.json").read_text(encoding="utf-8"))
        eujf = json.loads((rd / "eujf.json").read_text(encoding="utf-8"))
        timings = json.loads((rd / "timings.json").read_text(encoding="utf-8")) if (rd / "timings.json").exists() else {}
        meta = json.loads((rd / "scan.json").read_text(encoding="utf-8")) if (rd / "scan.json").exists() else {}
        label = meta.get("label") or analysis["summary"].get("label") or "scan"
        scans.append({"i": i, "dir": rd, "slug": slug(i, label), "label": label, "meta": meta,
                      "analysis": analysis, "eujf": eujf, "timings": timings})
    history = store.history(scans[0]["eujf"]["target"])
    cur = store.conn.cursor()
    for sc in scans:
        a, s = sc["analysis"], sc["slug"]
        counts = []
        for t in ("atg_eujf", "atg_nodes", "atg_edges"):
            cur.execute(store._q(f"SELECT COUNT(*) FROM {t} WHERE run_id = ?"), (a["run_id"],))
            counts.append(cur.fetchone()[0])
        sc["rows"] = dict(zip(("eujf", "nodes", "edges"), counts))
        sc["drawn_edges"] = sum(1 for e in a["graph"]["edges"] if e["rel"] != "RUNS_ON")
        # the files each phase wrote, so every phase can be opened on its own
        d = SITE / "scans" / s
        (d / "raw").mkdir(parents=True, exist_ok=True)
        for f in (sc["dir"] / "raw").glob("*.json"):
            shutil.copy(f, d / "raw" / f.name)
        for f in ("eujf.json", "analysis.json"):
            shutil.copy(sc["dir"] / f, d / f)
        others = [(f"Threat graph: {o['label']}", f"threat-graph-{o['slug']}.html") for o in scans if o is not sc]
        build_dashboard(a, sc["eujf"], history, SITE / f"threat-graph-{s}.html", sc["timings"], view="graph",
                        nav=[("Home", "index.html"), ("Full dashboard", f"dashboard-{s}.html")] + others)
        build_dashboard(a, sc["eujf"], history, SITE / f"dashboard-{s}.html", sc["timings"],
                        phase1_report=f"phase1-report-{s}.html",
                        nav=[("Home", "index.html"), ("Threat graph only", f"threat-graph-{s}.html"),
                             ("Phase 1 report", f"phase1-report-{s}.html"), ("EUJF (Phase 2)", f"scans/{s}/eujf.json")])
    store.close()
    first, last = scans[0], scans[-1]
    shutil.copy(SITE / f"threat-graph-{first['slug']}.html", SITE / "threat-graph.html")

    v, h = first["analysis"]["summary"], last["analysis"]["summary"]
    rows = [("Attack-path risk (sum of APCR)", "total_path_risk"), ("Findings", "findings"), ("Critical findings", None),
            ("Attack paths", "attack_paths"), ("Shadow endpoints", "shadow_endpoints")]

    def val(x, k):
        return x["by_severity"]["critical"] if k is None else x[k]
    if len(scans) > 1:
        red = 100 * (1 - h["total_path_risk"] / v["total_path_risk"]) if v["total_path_risk"] else 0
        nums = "".join(f"<tr><td>{t}</td><td>{val(v, k):g}</td><td>{val(h, k):g}</td></tr>" for t, k in rows)
        compare = f"""<div class="card"><b>{E(first['label'])} → {E(last['label'])}</b>
    <table class="nums"><thead><tr><th></th><th>{E(first['label'])}</th><th>{E(last['label'])}</th></tr></thead><tbody>{nums}</tbody></table>
    <span>Attack-path risk fell {red:.1f}% between the first and the latest scan.
    <a href="threat-graph-{last['slug']}.html">Threat graph of the latest scan</a></span></div>"""
    else:
        nums = "".join(f"<tr><td>{t}</td><td>{val(v, k):g}</td></tr>" for t, k in rows)
        compare = f"""<div class="card"><b>Scan: {E(first['label'])}</b>
    <table class="nums"><tbody>{nums}</tbody></table>
    <span>Scan again after the company applies fixes to see the trend.</span></div>"""

    conf = first["eujf"]["summary"].get("confidence", {})
    scan_rows = "".join(
        f"<tr><td>{sc['i']}</td><td><b>{E(sc['label'])}</b></td><td class='mono'>{E(sc['analysis']['run_id'])}</td>"
        f"<td class='num'>{sc['meta'].get('flows', '–')}</td><td class='num'>{sc['meta'].get('span_batches', '–')}</td>"
        f"<td class='num'>{sc['eujf']['summary']['endpoints']}</td><td class='num'>{sc['analysis']['summary']['findings']}</td>"
        f"<td class='num'>{sc['analysis']['summary']['attack_paths']}</td><td class='num'>{sc['analysis']['summary']['total_path_risk']:g}</td>"
        f"<td><a href='threat-graph-{sc['slug']}.html'>threat graph</a> · <a href='dashboard-{sc['slug']}.html'>dashboard</a></td></tr>"
        for sc in scans)
    s1 = first["slug"]
    phases = f"""
<div class="cards">
  <a class="card" href="phase1-report-{s1}.html"><b>1 · Extractor</b><span>Runtime traffic from the mitmproxy sidecar, OpenAPI from the
  services, Kubernetes manifests and gateway routes, OpenTelemetry spans from the Collector.
  Raw output: <code>scans/{s1}/raw/*.json</code></span></a>
  <a class="card" href="scans/{s1}/eujf.json"><b>2 · API Normalizer → EUJF</b><span>{first['eujf']['summary']['endpoints']} APIs as Extended
  Universal JSON Format records (confidence HIGH {conf.get('HIGH', 0)}, MEDIUM {conf.get('MEDIUM', 0)}, ZOMBIE {conf.get('ZOMBIE', 0)}),
  stored in PostgreSQL table <code>atg_eujf</code> ({first['rows']['eujf']} rows).</span></a>
  <a class="card" href="scans/{s1}/analysis.json"><b>3 · Analysis &amp; risk</b><span>{first['analysis']['summary']['rules_evaluated']} rules,
  {first['analysis']['summary']['findings']} findings, threat graph with {first['rows']['nodes']} nodes and {first['rows']['edges']} edges in
  <code>atg_nodes</code> / <code>atg_edges</code>, {first['analysis']['summary']['attack_paths']} attack paths from a recursive SQL query.</span></a>
  <a class="card" href="dashboard-{s1}.html"><b>4 · Output</b><span>API overview, risk summary, top vulnerabilities, trend &amp; insight,
  and the threat graph with propagated risk.</span></a>
</div>"""
    exp_cards = "".join(f'<a class="card" href="{E(href)}"><b>{E(t)}</b><span>{E(x)}</span></a>'
                        for t, href, x in experiment_pages())
    store_label = first["analysis"]["store"]
    is_pg = store_label.startswith("PostgreSQL")
    q1 = ('docker compose exec atg-postgres psql -U atg -c "SELECT api_id, method, endpoint, auth, confidence FROM atg_eujf ORDER BY run_id, api_id;"'
          if is_pg else "sqlite3 output/atg.db \"SELECT api_id, method, endpoint, auth, confidence FROM atg_eujf;\"")
    q2 = ('docker compose exec atg-postgres psql -U atg -c "SELECT type, COUNT(*) FROM atg_nodes GROUP BY type;"'
          if is_pg else "sqlite3 output/atg.db \"SELECT type, COUNT(*) FROM atg_nodes GROUP BY type;\"")
    body = f"""
<header class="head"><div class="eyebrow">Automatic API Security Design Review · two Docker deployments</div>
<h1>API Threat Graph</h1>
<p class="muted">The ATG platform (our Docker) joined the network of ShopLite, the company's system under review (its own Docker).
Customer traffic went through ATG's mitmproxy sidecar, the services sent their spans to ATG's OpenTelemetry Collector, and ATG read
the services' OpenAPI documents and the company's deployment manifests. Nothing left the company network.</p>
<div class="meta"><span>graph store {E(store_label)}</span><span>{len(scans)} scan{'s' if len(scans) > 1 else ''}</span>
<span>updated {time.strftime('%H:%M:%S')}</span></div>
</header>

<section class="hero">
  <a class="card main" href="threat-graph.html"><b>Open the threat graph</b>
    <span>{E(first['label'])}: {first['rows']['nodes']} nodes and {first['drawn_edges']} edges: who can reach which API, which weakness it has,
    and what an attacker gains. {v['findings']} findings, {v['attack_paths']} attack paths. Click any node or path.</span>
    <div class="gprev" inert>{_graph_svg(first['analysis'])}</div>
    <span class="go">Open threat-graph.html →</span></a>
  {compare}
</section>

<section><h2>The four phases on the first scan</h2>{phases}</section>

<section><h2>Scans</h2>
<div class="scroll"><table><thead><tr><th>#</th><th>Label</th><th>Run</th><th class="num">HTTP flows</th><th class="num">Span batches</th>
<th class="num">APIs</th><th class="num">Findings</th><th class="num">Paths</th><th class="num">Path risk</th><th>Pages</th></tr></thead>
<tbody>{scan_rows}</tbody></table></div></section>

<section><h2>How the two Dockers are connected</h2><div class="arch">{ARCH_SVG}
<p class="muted" style="margin:6px 8px 2px;font-size:13px">{ARCH_NOTE}</p></div></section>

<section><h2>Experiment results (Section IV)</h2>
<p class="muted">Computed earlier on three systems, two capture conditions and five seeds each. They ship with the code.</p>
<div class="cards">{exp_cards}</div></section>

<section><h2>Look inside PostgreSQL</h2>
<p class="muted">Open a second terminal in this folder. The EUJF records (Phase 2):</p>
<p><code class="cmd">{E(q1)}</code></p>
<p class="muted">The threat graph (Phase 3):</p>
<p><code class="cmd">{E(q2)}</code></p>
<p class="muted">Stop everything with STOP-Windows.bat or <code class="cmd">sh stop.sh</code>. These pages stay in <code>output/site/</code>.</p></section>"""
    write(SITE / "index.html", page("API Threat Graph", body, dash_css=True))
