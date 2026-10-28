"""
Entry point of the Docker image.

    docker compose up        ->  open http://localhost:8080

1. serves a progress page right away (port 8888 in the container, 8080 on your machine)
2. waits for the PostgreSQL graph store
3. runs Phases 1-4 on ShopLite as shipped (vulnerable), then on ShopLite with the fixes (hardened)
4. builds the pages: threat graph (before / after), full dashboards, Phase 1 reports,
   and the Section IV experiment results that ship with the code
5. keeps serving until you stop it (docker compose down)

Everything it writes also lands in ./output on your machine (output/site/index.html).
"""
from __future__ import annotations

import functools
import html
import http.server
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

from extractor.report import CSS as BASE_CSS  # noqa: E402
from atg.dashboard import CSS as DASH_CSS, NAV_CSS, _graph_svg  # noqa: E402

OUT = ROOT / "output"
SITE = OUT / "site"
PORT = int(os.environ.get("ATG_SERVE_PORT", "8888"))
PUBLIC_URL = os.environ.get("ATG_PUBLIC_URL", "http://localhost:8080")
E = html.escape

STEPS = [
    ("store", "Connect to the graph store"),
    ("vulnerable", "ShopLite as shipped: start 4 services, capture traffic, run Phases 1-4"),
    ("hardened", "ShopLite after the fixes: same again"),
    ("pages", "Build the threat graph pages"),
]
state = {"step": "store", "done": [], "line": "starting", "started": time.time(), "failed": None}

PAGE_CSS = """
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,250px),1fr));gap:10px}
.card{display:grid;gap:4px;align-content:start;border:1px solid var(--line);border-radius:8px;background:var(--surface);
  padding:14px 16px;text-decoration:none;color:var(--fg)}
a.card:hover{border-color:var(--accent)}
.card b{font:700 15px var(--f-display)}
.card span{font-size:13px;color:var(--muted);line-height:1.45}
.hero{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:10px}
@media (max-width:760px){.hero{grid-template-columns:1fr}}
.hero .card.main{border:2px solid var(--accent);padding:20px 22px}
.hero .card.main b{font-size:24px}
.hero .card.main .go{font:600 14px var(--f-body);color:var(--accent)}
.wrap a.card{color:var(--fg)}
.card a{color:var(--accent)}
.gprev{border:1px solid var(--line);border-radius:6px;background:var(--surface);pointer-events:none;margin:6px 0 2px}
.gprev svg{display:block;width:100%;height:250px}
.nums{width:100%;border-collapse:collapse;font-size:13.5px}
.nums th,.nums td{padding:5px 8px;border-bottom:1px solid var(--line);text-align:right;font-variant-numeric:tabular-nums}
.nums th:first-child,.nums td:first-child{text-align:left}
.steps{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.steps li{display:grid;grid-template-columns:22px minmax(0,1fr);gap:8px;align-items:start;font-size:14.5px}
.steps .ic{font:700 14px var(--f-mono)}
.steps .ok{color:var(--ok)} .steps .now{color:var(--accent)} .steps .wait{color:var(--muted)}
pre.log{white-space:pre-wrap;max-height:420px;overflow:auto;font-size:12px}
code.cmd{font:12.5px var(--f-mono);background:var(--surface-2);padding:2px 6px;border-radius:4px}
.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px}
.figs figure{margin:0;border:1px solid var(--line);border-radius:8px;background:#fff;padding:10px}
.figs img{width:100%;height:auto;display:block}
.figs figcaption{font:12.5px var(--f-mono);color:#5a6675;margin-top:6px}
.md table{border-collapse:collapse;font-size:13px}
.md th,.md td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
.md th{background:var(--surface-2)}
"""


def page(title: str, body: str, refresh: int | None = None, extra_css: str = "") -> str:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">' + meta
            + f"<title>{E(title)}</title>"
            '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
            '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=JetBrains+Mono:wght@400;600;700&family=Public+Sans:wght@400;600;700&display=swap">'
            f"<style>{extra_css or BASE_CSS}{NAV_CSS}{PAGE_CSS}</style></head><body><div class=\"wrap\">{body}</div></body></html>")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------- progress page
def progress_page() -> None:
    items = []
    for key, text in STEPS:
        if key in state["done"]:
            ic, cls = "✓", "ok"
        elif key == state["step"] and not state["failed"]:
            ic, cls = "›", "now"
        else:
            ic, cls = "·", "wait"
        items.append(f'<li><span class="ic {cls}">{ic}</span><span>{E(text)}</span></li>')
    took = int(time.time() - state["started"])
    if state["failed"]:
        log = ""
        lp = OUT / "logs" / "docker-run.log"
        if lp.exists():
            log = "\n".join(lp.read_text(encoding="utf-8", errors="replace").splitlines()[-60:])
        body = f"""
<header class="head"><div class="eyebrow">API Threat Graph · Docker</div><h1>The run stopped with an error</h1>
<p class="muted">{E(state['failed'])}</p></header>
<section><ul class="steps">{''.join(items)}</ul></section>
<section><h2>Last lines of the log</h2><pre class="log">{E(log)}</pre>
<p class="muted">Full log: <code class="cmd">output/logs/docker-run.log</code>. Try again with
<code class="cmd">docker compose down</code> then <code class="cmd">docker compose up</code>.</p></section>"""
        write(SITE / "index.html", page("API Threat Graph: error", body))
        return
    body = f"""
<header class="head"><div class="eyebrow">API Threat Graph · Docker</div>
<h1>Running the four phases…</h1>
<p class="muted">This page refreshes by itself and shows the threat graph when the run finishes (about one minute).</p></header>
<section><ul class="steps">{''.join(items)}</ul>
<p class="muted mono" style="font-size:12.5px">{took} s · {E(state['line'][:160])}</p></section>"""
    write(SITE / "index.html", page("API Threat Graph: running", body, refresh=3))


# ---------------------------------------------------------------- web server
class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, *args):
        pass


def serve() -> None:
    SITE.mkdir(parents=True, exist_ok=True)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), functools.partial(Handler, directory=str(SITE)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


# ---------------------------------------------------------------- run
def log(line: str, fh) -> None:
    print(line, flush=True)
    fh.write(line + "\n")
    fh.flush()


def graph_store(fh) -> str | None:
    url = os.environ.get("ATG_GRAPH_STORE", "")
    if not url.startswith(("postgresql://", "postgres://")):
        return None
    import psycopg
    deadline = time.time() + 90
    last = None
    while time.time() < deadline:
        try:
            with psycopg.connect(url, connect_timeout=3) as c:
                if os.environ.get("ATG_RESET", "1") != "0":  # every start is a fresh before/after demo
                    for t in ("atg_paths", "atg_findings", "atg_edges", "atg_nodes", "atg_runs"):
                        c.execute(f"DROP TABLE IF EXISTS {t}")
            log(f"graph store: PostgreSQL at {url.split('@')[-1]}", fh)
            return url
        except Exception as exc:  # not up yet
            last = exc
            state["line"] = "waiting for PostgreSQL"
            progress_page()
            time.sleep(1.5)
    log(f"PostgreSQL not reachable ({last}); using the built-in SQLite store instead", fh)
    os.environ.pop("ATG_GRAPH_STORE", None)
    return None


def run_scenario(scenario: str, fh) -> None:
    state["step"] = scenario
    progress_page()
    proc = subprocess.Popen([sys.executable, "-u", "scripts/run_demo.py", "--scenario", scenario],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=os.environ.copy())
    last_page = 0.0
    for raw in proc.stdout:
        line = raw.rstrip()
        log(line, fh)
        if line.strip():
            state["line"] = f"{scenario}: {line.strip()}"
        if time.time() - last_page > 1:
            progress_page()
            last_page = time.time()
    if proc.wait() != 0:
        raise RuntimeError(f"the {scenario} run failed (exit code {proc.returncode})")
    shutil.copy(OUT / "report.html", SITE / f"phase1-report-{scenario}.html")
    state["done"].append(scenario)


# ---------------------------------------------------------------- pages
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
    """Copy the Section IV results that ship with the code; return cards (title, href, text)."""
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


def build_pages(store_url: str | None, fh) -> None:
    state["step"] = "pages"
    progress_page()
    from atg.dashboard import build_dashboard
    from atg.graphstore import GraphStore

    runs = sorted(p for p in (OUT / "runs").iterdir() if p.is_dir())[-2:]
    store = GraphStore(store_url or f"sqlite:///{OUT / 'atg.db'}")
    info = {}
    for scen, rd in zip(("vulnerable", "hardened"), runs):
        analysis = json.loads((rd / "analysis.json").read_text(encoding="utf-8"))
        eujf = json.loads((rd / "eujf.json").read_text(encoding="utf-8"))
        timings = json.loads((rd / "timings.json").read_text(encoding="utf-8")) if (rd / "timings.json").exists() else {}
        history = store.history(eujf["target"])
        other = "hardened" if scen == "vulnerable" else "vulnerable"
        g_nav = [("Home", "index.html"), ("Full dashboard", f"dashboard-{scen}.html"),
                 ("Before fixes" if other == "vulnerable" else "After fixes", f"threat-graph-{other}.html")]
        d_nav = [("Home", "index.html"), ("Threat graph only", f"threat-graph-{scen}.html"),
                 (f"Phase 1 report", f"phase1-report-{scen}.html")]
        build_dashboard(analysis, eujf, history, SITE / f"threat-graph-{scen}.html", timings, view="graph", nav=g_nav)
        build_dashboard(analysis, eujf, history, SITE / f"dashboard-{scen}.html", timings,
                        phase1_report=f"phase1-report-{scen}.html", nav=d_nav)
        cur = store.conn.cursor()
        counts = []
        for t in ("atg_nodes", "atg_edges"):
            cur.execute(store._q(f"SELECT COUNT(*) FROM {t} WHERE run_id = ?"), (analysis["run_id"],))
            counts.append(cur.fetchone()[0])
        drawn = sum(1 for e in analysis["graph"]["edges"] if e["rel"] != "runs_on")
        info[scen] = {"s": analysis["summary"], "nodes": counts[0], "edges": drawn, "stored_edges": counts[1],
                      "store": analysis["store"], "svg": _graph_svg(analysis)}
    store.close()
    shutil.copy(SITE / "threat-graph-vulnerable.html", SITE / "threat-graph.html")

    v, h = info["vulnerable"], info["hardened"]
    red = 100 * (1 - h["s"]["total_path_risk"] / v["s"]["total_path_risk"]) if v["s"]["total_path_risk"] else 0
    rows = [("Attack-path risk (sum of APCR)", "total_path_risk"), ("Findings", "findings"),
            ("Critical findings", None), ("Attack paths", "attack_paths"), ("Shadow endpoints", "shadow_endpoints")]

    def val(x, k):
        return x["s"]["by_severity"]["critical"] if k is None else x["s"][k]
    nums = "".join(f"<tr><td>{t}</td><td>{val(v, k):g}</td><td>{val(h, k):g}</td></tr>" for t, k in rows)
    exp_cards = "".join(f'<a class="card" href="{E(href)}"><b>{E(t)}</b><span>{E(x)}</span></a>'
                        for t, href, x in experiment_pages())
    is_pg = v["store"].startswith("PostgreSQL")
    query = ('docker compose exec postgres psql -U atg -c "SELECT type, COUNT(*) FROM atg_nodes GROUP BY type;"'
             if is_pg else "sqlite3 output/atg.db \"SELECT type, COUNT(*) FROM atg_nodes GROUP BY type;\"")
    body = f"""
<header class="head"><div class="eyebrow">Automatic API Security Design Review · prototype running in Docker</div>
<h1>API Threat Graph</h1>
<p class="muted">ShopLite, a demo shop of four microservices, ran inside this container. The tool captured its traffic,
read its OpenAPI specs, Kubernetes manifests and traces, merged them, checked {v['s']['rules_evaluated']} rules,
built the threat graph and ranked the attack paths. Then it did the same on ShopLite with the recommended fixes applied.</p>
<div class="meta"><span>graph store {E(v['store'])}</span><span>run finished in {int(time.time() - state['started'])} s</span></div>
</header>

<section class="hero">
  <a class="card main" href="threat-graph.html"><b>Open the threat graph</b>
    <span>{v['nodes']} nodes and {v['edges']} edges: who can reach which API, which weakness it has, and what an attacker gains.
    {v['s']['findings']} findings, {v['s']['attack_paths']} attack paths. Click any node or path.</span>
    <div class="gprev" inert>{v['svg']}</div>
    <span class="go">Open threat-graph.html →</span></a>
  <div class="card"><b>Before and after the fixes</b>
    <table class="nums"><thead><tr><th></th><th>before</th><th>after</th></tr></thead><tbody>{nums}</tbody></table>
    <span>Attack-path risk fell {red:.1f}%. <a href="threat-graph-hardened.html">Threat graph after the fixes</a></span></div>
</section>

<section><h2>The prototype's own pages</h2>
<div class="cards">
  <a class="card" href="dashboard-vulnerable.html"><b>Full dashboard, before fixes</b><span>Risk summary, top vulnerabilities with evidence and standards, attack paths, threat graph, fix plan, API inventory, rule catalog.</span></a>
  <a class="card" href="dashboard-hardened.html"><b>Full dashboard, after fixes</b><span>Same page for the fixed build. The trend chart shows both runs.</span></a>
  <a class="card" href="phase1-report-vulnerable.html"><b>Phase 1 extractor report</b><span>What each of the four sources found: traffic, OpenAPI, Kubernetes, traces.</span></a>
  <a class="card" href="threat-graph-hardened.html"><b>Threat graph after fixes</b><span>{h['nodes']} nodes, {h['s']['findings']} findings, {h['s']['attack_paths']} attack paths left.</span></a>
</div></section>

<section><h2>Experiment results (Section IV)</h2>
<p class="muted">Computed earlier on three systems, two capture conditions and five seeds each. They ship with the code, so they open instantly.</p>
<div class="cards">{exp_cards}</div></section>

<section><h2>Where the threat graph is stored</h2>
<p class="muted">Each run's graph is saved in the tables <code>atg_nodes</code> and <code>atg_edges</code>, and the attack paths
come from a recursive SQL query on them. The run before the fixes has {v['nodes']} nodes and {v['stored_edges']} edges there;
the drawing leaves out the {v['stored_edges'] - v['edges']} <code>runs_on</code> edges (endpoint to its service) because the columns already show them.
To look inside, open a second terminal in this folder and run:</p>
<p><code class="cmd">{E(query)}</code></p>
<p class="muted">Files from this run are also in the <code>output</code> folder next to <code>docker-compose.yml</code>.
Stop everything with <code class="cmd">docker compose down</code> (or STOP-Windows.bat).</p></section>"""
    write(SITE / "index.html", page("API Threat Graph", body, extra_css=DASH_CSS))
    state["done"].append("pages")


def main() -> int:
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    for d in ("runs", "site"):
        shutil.rmtree(OUT / d, ignore_errors=True)
    (OUT / "atg.db").unlink(missing_ok=True)
    (OUT / "logs").mkdir(parents=True, exist_ok=True)
    serve()
    progress_page()
    print(f"\n  Progress page: {PUBLIC_URL}\n", flush=True)
    with open(OUT / "logs" / "docker-run.log", "w", encoding="utf-8") as fh:
        try:
            url = graph_store(fh)
            state["done"].append("store")
            run_scenario("vulnerable", fh)
            run_scenario("hardened", fh)
            build_pages(url, fh)
        except Exception as exc:
            state["failed"] = str(exc)
            log(f"ERROR: {exc}", fh)
            progress_page()
            print(f"\n  The run failed. Details: {PUBLIC_URL} and output/logs/docker-run.log\n", flush=True)
    if not state["failed"]:
        bar = "=" * 60
        print(f"\n{bar}\n  Ready.  Open {PUBLIC_URL}\n  Threat graph: {PUBLIC_URL}/threat-graph.html\n"
              f"  Stop with Ctrl+C, then: docker compose down\n{bar}\n", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
