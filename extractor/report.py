"""
Phase 1 visual report: output/report.html

Reads output/raw/*.json and draws one self-contained page so a teammate can
see what each extractor found without reading JSON:

  - run summary in the same 4 rows as the architecture diagram
  - service map (exposure + who-calls-whom from traces)
  - endpoint coverage across sources (preview of what Phase 2 will merge)
  - per-source detail tables, plus the raw files

Pure Python string building, no template engine, no JS framework.
"""
from __future__ import annotations

import html
import json
from collections import defaultdict
from pathlib import Path

from .common import match_key

E = html.escape
SOURCES = [
    ("runtime_traffic", "MITPROXY", "Runtime traffic", "traffic"),
    ("openapi", "OPENAPI", "OpenAPI discovery", "spec"),
    ("infrastructure", "K8S MANIFESTS", "Infrastructure & gateway", "infra"),
    ("callchain", "OPENTELEMETRY", "Distributed trace / call chain", "trace"),
]


def _load(raw_dir: Path) -> dict:
    data = {}
    for name, *_ in SOURCES:
        p = raw_dir / f"{name}.json"
        data[name] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    m = raw_dir / "manifest.json"
    data["manifest"] = json.loads(m.read_text(encoding="utf-8")) if m.exists() else {}
    return data


def _recs(doc, kind=None):
    if not doc:
        return []
    return [r for r in doc["records"] if kind is None or r.get("kind") == kind]


def _chip(text, tone="neutral", title=None):
    t = f' title="{E(title)}"' if title else ""
    return f'<span class="chip {tone}"{t}>{E(str(text))}</span>'


SENSITIVE_FORMATS = {"email", "phone", "card_number", "jwt"}


def _sensitive_fields(shape, prefix="") -> list[str]:
    out = []
    if isinstance(shape, dict):
        for k, v in shape.items():
            out += _sensitive_fields(v, f"{prefix}{k}.")
    elif isinstance(shape, list) and shape:
        out += _sensitive_fields(shape[0], prefix.rstrip(".") + "[].")
    elif isinstance(shape, str):
        fmts = {p.split(":", 1)[1] for p in shape.split("|") if ":" in p}
        for f in fmts & SENSITIVE_FORMATS:
            out.append(f"{prefix.rstrip('.')} ({f})")
    return out


# ---------------------------------------------------------------------------
# service map
# ---------------------------------------------------------------------------
def _service_map_svg(d: dict) -> str:
    infra, cc, oa = d["infrastructure"], d["callchain"], d["openapi"]
    workloads = {w["name"]: w for w in _recs(infra, "workload")}
    exposure = defaultdict(list)
    for e in _recs(infra, "exposure"):
        exposure[e["workload"]].append(e)
    edges = [(e["from"], e["to"], e["calls"]) for e in _recs(cc, "edge")]
    entries = _recs(cc, "entrypoint")
    spec_by_svc = defaultdict(set)
    for s in _recs(oa, "spec"):
        spec_by_svc[s["service"]].add(s["origin"])

    nodes = set(workloads) | {s["service"] for s in _recs(cc, "service")} | {b for _, b, _ in edges}
    ingress_targets = [w for w, ex in exposure.items()
                       if any(x["level"] == "internet" and x["via"][0].startswith("Ingress") for x in ex)]
    node_exposed = [w for w, ex in exposure.items() if any(x["level"] == "node" for x in ex)]
    # entry points that are not reached from the ingress = something inside the cluster calls them
    inside_entries = [e for e in entries if e["service"] not in ingress_targets]

    # depth = longest path from an ingress target along traced edges
    depth = {n: 1 for n in ingress_targets}
    for _ in range(len(nodes) + 1):
        changed = False
        for a, b, _ in edges:
            if a in depth and depth.get(b, 0) < depth[a] + 1 and depth[a] < 8:
                depth[b] = depth[a] + 1
                changed = True
        if not changed:
            break
    max_d = max(depth.values(), default=1)
    for n in sorted(nodes):
        depth.setdefault(n, max_d + 1 if n not in ingress_targets else 1)

    cols = defaultdict(list)
    for n in sorted(nodes, key=lambda x: (depth[x], x)):
        cols[depth[n]].append(n)
    ncols = max(cols) + 1
    colw, nw, nh, rowh, top = 268, 182, 70, 112, 46
    height = max(len(v) for v in cols.values()) * rowh + top + 40
    height = max(height, 3 * rowh + top)
    width = ncols * colw + 20
    pos = {}
    for c, members in cols.items():
        span = len(members) * rowh
        y0 = top + (height - top - 30 - span) / 2
        for i, n in enumerate(members):
            pos[n] = (20 + c * colw, y0 + i * rowh + (rowh - nh) / 2)
    pos["__internet"] = (20, top + 14)
    if inside_entries:
        pos["__inside"] = (20, height - nh - 34)

    def anchor_r(n):
        x, y = pos[n]
        w = 150 if n.startswith("__") else nw
        return x + w, y + nh / 2

    def anchor_l(n):
        x, y = pos[n]
        return x, y + nh / 2

    parts = []
    for c in range(ncols):
        label = "Outside" if c == 0 else ("Edge / gateway" if c == 1 else f"Tier {c}")
        parts.append(f'<text class="colhead" x="{20 + c * colw}" y="22">{label}</text>')

    def column_of(n):
        return 0 if n.startswith("__") else depth[n]

    def curve(a, b, cls, label=None, label_t=0.5):
        (x1, y1), (x2, y2) = anchor_r(a), anchor_l(b)
        ca, cb = column_of(a), column_of(b)
        between = [pos[n] for n in nodes if ca < depth[n] < cb]
        if x2 <= x1:  # same or backward column: loop below
            dx = 60
            path = f"M{x1},{y1} C{x1 + dx},{y1 + 70} {x2 - dx},{y2 + 70} {x2},{y2}"
            lx, ly = (x1 + x2) / 2, max(y1, y2) + 52
        elif between:
            # skip over intermediate columns: bend above or below the nodes in the way
            top_y = min(y for _, y in between) - 18
            bot_y = max(y for _, y in between) + nh + 18
            wy = top_y if abs((y1 + y2) / 2 - top_y) <= abs((y1 + y2) / 2 - bot_y) else bot_y
            if cls == "inside":  # keep the untraced-caller lane apart from trace edges
                wy += 18 if wy == bot_y else -18
            xs = sorted(x for x, _ in between)
            xa, xb = xs[0] - 30, xs[-1] + nw + 30
            path = (f"M{x1},{y1} C{x1 + 40},{y1} {xa - 40},{wy} {xa},{wy} "
                    f"L{xb},{wy} C{xb + 40},{wy} {x2 - 40},{y2} {x2},{y2}")
            lx, ly = (xa + xb) / 2, wy - 6
        else:
            mx = (x1 + x2) / 2
            path = f"M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}"
            lx = x1 + (x2 - x1) * label_t
            ly = y1 + (y2 - y1) * label_t - 6
        parts.append(f'<path class="edge {cls}" d="{path}" marker-end="url(#arr-{cls})"/>')
        if label:
            parts.append(f'<text class="elabel {cls}" x="{lx:.0f}" y="{ly:.0f}" text-anchor="middle">{E(label)}</text>')

    for t in ingress_targets:
        ing = next((x for x in exposure[t] if x["via"][0].startswith("Ingress")), None)
        curve("__internet", t, "ingress", "Ingress" + (" (TLS)" if ing and ing.get("tls") else " (no TLS)"), 0.5)
    for t in node_exposed:
        curve("__internet", t, "nodeport", "NodePort", 0.82)
    for e in inside_entries:
        curve("__inside", e["service"], "inside", f"{e['operation']}  ×{e['traces']}", 0.62)
    for a, b, n in edges:
        if a in pos and b in pos:
            curve(a, b, "trace", f"{n} calls", 0.5)

    # nodes
    x, y = pos["__internet"]
    parts.append(f'<g class="node pseudo"><rect x="{x}" y="{y}" width="150" height="{nh}" rx="6"/>'
                 f'<text x="{x + 14}" y="{y + 30}" class="nname">Internet</text>'
                 f'<text x="{x + 14}" y="{y + 50}" class="nsub">public clients</text></g>')
    if "__inside" in pos:
        x, y = pos["__inside"]
        parts.append(f'<g class="node pseudo"><rect x="{x}" y="{y}" width="150" height="{nh}" rx="6"/>'
                     f'<text x="{x + 14}" y="{y + 30}" class="nname">In-cluster caller</text>'
                     f'<text x="{x + 14}" y="{y + 50}" class="nsub">job / untraced client</text></g>')
    for n in sorted(nodes):
        x, y = pos[n]
        levels = {e["level"] for e in exposure.get(n, [])}
        level = "internet" if "internet" in levels else "node" if "node" in levels else "internal"
        w = workloads.get(n)
        netpol = bool(w and w.get("network_policies"))
        spec = "live spec" if "live" in spec_by_svc[n] else "file spec" if "file" in spec_by_svc[n] else "no spec"
        cls = f"node lvl-{level}" + (" unknown" if not w else "")
        parts.append(f'<g class="{cls}"><rect x="{x}" y="{y}" width="{nw}" height="{nh}" rx="6"/>'
                     f'<rect class="stripe" x="{x}" y="{y}" width="5" height="{nh}" rx="2"/>'
                     f'<text x="{x + 16}" y="{y + 25}" class="nname">{E(n)}</text>'
                     f'<text x="{x + 16}" y="{y + 45}" class="nsub">{level} · {spec}</text>'
                     f'<text x="{x + 16}" y="{y + 60}" class="nsub dim">'
                     f'{"network policy" if netpol else "no network policy" if w else "not in manifests"}</text></g>')

    markers = "".join(
        f'<marker id="arr-{c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path class="mk {c}" d="M0,0 L10,5 L0,10 z"/></marker>'
        for c in ("ingress", "nodeport", "inside", "trace"))
    return (f'<svg class="smap" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="Service map built from manifests and traces"><defs>{markers}</defs>{"".join(parts)}</svg>')


# ---------------------------------------------------------------------------
# endpoint coverage (preview of the Phase 2 join)
# ---------------------------------------------------------------------------
def _coverage(d: dict):
    rt, oa, cc, infra = d["runtime_traffic"], d["openapi"], d["callchain"], d["infrastructure"]
    gateways = {e["workload"] for e in _recs(infra, "exposure") if e["via"][0].startswith("Ingress")}
    rows: dict[tuple, dict] = {}

    def row(svc, method, path):
        k = (svc, match_key(method, path))
        r = rows.setdefault(k, {"service": svc, "method": method.upper(), "path": path,
                                "spec": [], "traffic": 0, "trace": 0, "auth_missing": 0, "deprecated": False})
        if "{" in path and "{int}" not in path and "{id}" not in path:
            r["path"] = path  # prefer the spec's parameter names
        return r

    for s in _recs(oa, "spec"):
        for o in s["operations"]:
            r = row(s["service"], o["method"], o["path"])
            r["spec"].append(f'{s["origin"]} v{s["api_version"]}' if s["origin"] == "file" else s["origin"])
            r["deprecated"] |= o["deprecated"]
            r["spec_auth"] = o["auth_declared"]
    for e in _recs(rt, "endpoint"):
        if e["service"] in gateways:
            continue
        r = row(e["service"], e["method"], e["path_template"])
        r["traffic"] += e["hits"]
        r["auth_missing"] += e["auth"]["authorization_header_missing"]
    for s in _recs(cc, "service"):
        if s["service"] in gateways:
            continue
        for op in s["served_operations"]:
            method, _, path = op["operation"].partition(" ")
            if path.startswith("/"):
                row(s["service"], method, path)["trace"] += op["count"]

    out = []
    for r in sorted(rows.values(), key=lambda x: (x["service"], x["path"], x["method"])):
        seen = r["traffic"] or r["trace"]
        if r["spec"] and seen:
            r["status"] = ("Documented & observed", "ok")
        elif seen:
            r["status"] = ("Observed, in no spec", "warn")
        else:
            r["status"] = ("Documented, never observed", "info")
        out.append(r)
    return out, gateways


def _gateway_rows(d: dict, gateways: set[str]):
    rt, infra = d["runtime_traffic"], d["infrastructure"]
    traffic = [e for e in _recs(rt, "endpoint") if e["service"] in gateways]
    rows, matched = [], set()
    for r in sorted(_recs(infra, "gateway_route"), key=lambda x: x["match_prefix"]):
        hits = [e for e in traffic if e["path_template"].startswith(r["match_prefix"])]
        matched.update(id(e) for e in hits)
        rows.append({**r, "paths": hits})
    unrouted = [e for e in traffic if id(e) not in matched]
    return rows, unrouted


# ---------------------------------------------------------------------------
# page
# ---------------------------------------------------------------------------
CSS = """
/* Layout: a single reading column (max 1120px) — run summary, map, coverage, then tabbed source detail. */
:root{
  --bg:#f4f6f8; --surface:#ffffff; --surface-2:#eef1f4; --fg:#17212b; --muted:#5a6675; --line:#d9dfe6;
  --accent:#cf5f1f; --accent-soft:#fbe8dc;
  --src-traffic:#0e7490; --src-spec:#3f7a34; --src-infra:#2f6690; --src-trace:#7b45b5;
  --ok:#2c7a4b; --ok-soft:#e1f2e7; --warn:#a85d00; --warn-soft:#fbefd9; --crit:#b8262d; --crit-soft:#fbe3e4;
  --info:#4a5868; --info-soft:#e8ecf0;
  --f-display:"Archivo",ui-sans-serif,system-ui,sans-serif;
  --f-body:"Public Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  --f-mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --bg:#0e1319; --surface:#151c24; --surface-2:#1b242e; --fg:#e4e9ef; --muted:#97a3b2; --line:#29343f;
  --accent:#f08a4b; --accent-soft:#3a2416;
  --src-traffic:#4cc3d9; --src-spec:#8ccf7e; --src-infra:#7fb3dc; --src-trace:#c09cf2;
  --ok:#5fcf8a; --ok-soft:#163323; --warn:#f0b04f; --warn-soft:#3a2a10; --crit:#f2777c; --crit-soft:#3c1a1c;
  --info:#a9b6c4; --info-soft:#232d38; color-scheme:dark}}
:root[data-theme="dark"]{
  --bg:#0e1319; --surface:#151c24; --surface-2:#1b242e; --fg:#e4e9ef; --muted:#97a3b2; --line:#29343f;
  --accent:#f08a4b; --accent-soft:#3a2416;
  --src-traffic:#4cc3d9; --src-spec:#8ccf7e; --src-infra:#7fb3dc; --src-trace:#c09cf2;
  --ok:#5fcf8a; --ok-soft:#163323; --warn:#f0b04f; --warn-soft:#3a2a10; --crit:#f2777c; --crit-soft:#3c1a1c;
  --info:#a9b6c4; --info-soft:#232d38; color-scheme:dark}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font:15px/1.55 var(--f-body);margin:0}
.wrap{max-width:1120px;margin:0 auto;padding-inline:20px;padding-block:28px 64px;display:grid;gap:36px}
h1,h2,h3{font-family:var(--f-display);text-wrap:balance;margin:0;letter-spacing:-.01em}
h1{font-size:clamp(26px,4vw,36px);font-weight:700;line-height:1.15}
h2{font-size:21px;font-weight:700}
h3{font-size:15px;font-weight:700}
p{margin:0;max-width:68ch}
.muted{color:var(--muted)}
.mono,code{font-family:var(--f-mono);font-size:.86em}
.eyebrow{font:600 12px/1 var(--f-mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent)}
section{display:grid;gap:14px;min-width:0}
.head{display:grid;gap:12px}
.meta{display:flex;flex-wrap:wrap;gap:6px 18px;font:13px var(--f-mono);color:var(--muted)}
/* pipeline strip mirrors Fig. 1 */
.pipe{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.stage{border:1px solid var(--line);border-radius:6px;padding:10px 12px;background:var(--surface);display:grid;gap:2px;min-width:0}
.stage b{font:700 13px var(--f-display)}
.stage span{font-size:12px;color:var(--muted)}
.stage.now{border-color:var(--accent);background:var(--accent-soft)}
.stage.now span{color:var(--fg)}
@media (max-width:640px){.pipe{grid-template-columns:repeat(2,minmax(0,1fr))}}
/* source rows */
.sources{display:grid;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.src{display:grid;grid-template-columns:150px minmax(0,1fr) auto;gap:16px;align-items:center;background:var(--surface);padding:14px 16px}
.src .tool{font:700 12px var(--f-mono);letter-spacing:.06em;display:flex;align-items:center;gap:8px}
.src .tool i{width:10px;height:10px;border-radius:2px;display:inline-block;background:var(--c)}
.src .what{display:grid;gap:4px;min-width:0}
.src .nums{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:13px;color:var(--muted)}
.src .nums b{color:var(--fg);font-variant-numeric:tabular-nums}
.src .warnings{font-size:12.5px;color:var(--warn)}
.src .time{font:12px var(--f-mono);color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}
@media (max-width:640px){.src{grid-template-columns:1fr}.src .time{text-align:left}}
.c-traffic{--c:var(--src-traffic)}.c-spec{--c:var(--src-spec)}.c-infra{--c:var(--src-infra)}.c-trace{--c:var(--src-trace)}
/* service map */
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--surface)}
.smap{display:block;font-family:var(--f-body)}
.smap .colhead{font:600 11px var(--f-mono);letter-spacing:.08em;text-transform:uppercase;fill:var(--muted)}
.smap .node rect{fill:var(--surface-2);stroke:var(--line)}
.smap .node.pseudo rect{fill:var(--surface);stroke-dasharray:4 3;stroke:var(--muted)}
.smap .node .stripe{stroke:none}
.smap .lvl-internet .stripe{fill:var(--crit)}
.smap .lvl-node .stripe{fill:var(--warn)}
.smap .lvl-internal .stripe{fill:var(--ok)}
.smap .nname{font:700 13.5px var(--f-display);fill:var(--fg)}
.smap .nsub{font-size:11.5px;fill:var(--muted)}
.smap .nsub.dim{opacity:.85}
.smap .edge{fill:none;stroke-width:1.6}
.smap .edge.trace{stroke:var(--src-trace)}
.smap .edge.ingress{stroke:var(--crit)}
.smap .edge.nodeport{stroke:var(--warn);stroke-dasharray:6 4}
.smap .edge.inside{stroke:var(--muted);stroke-dasharray:3 3}
.smap .mk.trace{fill:var(--src-trace)}.smap .mk.ingress{fill:var(--crit)}.smap .mk.nodeport{fill:var(--warn)}.smap .mk.inside{fill:var(--muted)}
.smap .elabel{font:11px var(--f-mono);paint-order:stroke;stroke:var(--surface);stroke-width:4px}
.smap .elabel.trace{fill:var(--src-trace)}.smap .elabel.ingress{fill:var(--crit)}.smap .elabel.nodeport{fill:var(--warn)}.smap .elabel.inside{fill:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12.5px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:18px;height:0;border-top:2px solid var(--c);display:inline-block}
.legend i.dash{border-top-style:dashed}
.legend i.box{width:10px;height:10px;border:0;background:var(--c);border-radius:2px}
/* tables */
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{font:600 11px var(--f-mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap;background:var(--surface)}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.num{font-variant-numeric:tabular-nums;text-align:right;font-family:var(--f-mono);font-size:12.5px}
th.num{text-align:right}
td.path{font-family:var(--f-mono);font-size:12.5px;word-break:break-all;min-width:180px}
.method{font:700 11px var(--f-mono);letter-spacing:.04em}
.svc-group td{background:var(--surface-2);font:700 13px var(--f-display);padding-top:10px}
.chip{display:inline-block;font:600 11.5px/1.6 var(--f-body);padding:0 7px;border-radius:999px;white-space:nowrap;background:var(--info-soft);color:var(--info);margin:1px 2px 1px 0}
.chip.ok{background:var(--ok-soft);color:var(--ok)}
.chip.warn{background:var(--warn-soft);color:var(--warn)}
.chip.crit{background:var(--crit-soft);color:var(--crit)}
.chip.info{background:var(--info-soft);color:var(--info)}
.counts{display:flex;flex-wrap:wrap;gap:8px}
.count{border:1px solid var(--line);border-radius:6px;padding:8px 12px;background:var(--surface);display:grid;gap:0}
.count b{font:700 22px var(--f-display);font-variant-numeric:tabular-nums}
.count span{font-size:12px;color:var(--muted)}
.note{font-size:13px;color:var(--muted);border-left:3px solid var(--accent);padding:2px 0 2px 12px;max-width:80ch}
/* tabs */
.tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line)}
.tab{font:600 13px var(--f-body);color:var(--muted);background:none;border:0;border-bottom:2px solid transparent;padding:10px 12px;cursor:pointer;display:inline-flex;gap:8px;align-items:center}
.tab i{width:9px;height:9px;border-radius:2px;background:var(--c)}
.tab[aria-selected="true"]{color:var(--fg);border-bottom-color:var(--c)}
.tab:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.panel{display:grid;gap:18px;padding-top:6px;min-width:0}
details{border:1px solid var(--line);border-radius:6px;background:var(--surface)}
summary{cursor:pointer;padding:10px 14px;font-weight:600;font-size:13.5px}
pre{margin:0;padding:12px 14px;overflow:auto;max-height:420px;font:12px/1.5 var(--f-mono);border-top:1px solid var(--line);background:var(--surface-2)}
.chain{font:12.5px/1.8 var(--f-mono);padding:12px 14px;background:var(--surface);border:1px solid var(--line);border-radius:6px;overflow-x:auto}
.chain .n{color:var(--muted)}
.chain .svc{font-weight:700}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:18px}
.files td:first-child{font-family:var(--f-mono);font-size:12.5px}
.sha{font:11px var(--f-mono);color:var(--muted);word-break:break-all}
"""

JS = """
(function(){
  var tabs=[].slice.call(document.querySelectorAll('.tab'));
  function show(id){tabs.forEach(function(t){var on=t.dataset.panel===id;t.setAttribute('aria-selected',on);
    document.getElementById(t.dataset.panel).hidden=!on;});
    try{localStorage.setItem('atg-tab',id)}catch(e){}}
  tabs.forEach(function(t){t.addEventListener('click',function(){show(t.dataset.panel)})});
  var saved=null;try{saved=localStorage.getItem('atg-tab')}catch(e){}
  var hash=(location.hash||'').slice(1);
  show(document.getElementById(hash)?hash:(saved&&document.getElementById(saved)?saved:tabs[0].dataset.panel));
})();
"""


def _table(head: list[str], rows: list[list[str]], num_cols=(), cls="") -> str:
    th = "".join(f'<th class="{"num" if i in num_cols else ""}">{h}</th>' for i, h in enumerate(head))
    body = "".join("<tr>" + "".join(
        f'<td class="{"num" if i in num_cols else ""}">{c}</td>' for i, c in enumerate(r)) + "</tr>" for r in rows)
    return f'<div class="scroll"><table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def _status_chips(codes: dict) -> str:
    out = []
    for code, n in codes.items():
        tone = "ok" if code.startswith("2") else "warn" if code.startswith("4") else "crit" if code.startswith("5") else "info"
        out.append(_chip(f"{code} ×{n}", tone))
    return "".join(out)


def _traffic_panel(d):
    rt = d["runtime_traffic"]
    if not rt:
        return "<p class='muted'>No runtime traffic file.</p>"
    rows, last = [], None
    for e in rt["records"]:
        if e["service"] != last:
            rows.append(e["service"])
            last = e["service"]
        sens = _sensitive_fields(e["response"]["body_shape"])
        auth = (_chip(f'no token ×{e["auth"]["authorization_header_missing"]}', "warn")
                if e["auth"]["authorization_header_missing"] else "") + \
               (_chip(", ".join(e["auth"]["schemes"]) + f' ×{e["auth"]["authorization_header_seen"]}', "info")
                if e["auth"]["authorization_header_seen"] else "")
        rows.append([
            f'<span class="method">{E(e["method"])}</span>',
            E(e["path_template"]) + (f'<br><span class="muted">?{E(", ".join(e["query_params"]))}</span>' if e["query_params"] else ""),
            str(e["hits"]),
            _status_chips(e["status_codes"]),
            auth,
            "".join(_chip(s, "crit", "value never stored, only its type") for s in sens) or '<span class="muted">–</span>',
            "".join(_chip(c) for c in e["capture_points"]),
        ])
    head = ["Method", "Path template", "Hits", "Status", "Authorization", "Personal data in response", "Seen at"]
    body = []
    for r in rows:
        if isinstance(r, str):
            body.append(f'<tr class="svc-group"><td colspan="{len(head)}">{E(r)}</td></tr>')
        else:
            body.append("<tr>" + "".join(
                f'<td class="{"num" if i == 2 else "path" if i == 1 else ""}">{c}</td>' for i, c in enumerate(r)) + "</tr>")
    th = "".join(f'<th class="{"num" if i == 2 else ""}">{h}</th>' for i, h in enumerate(head))
    st = rt["stats"]
    intro = (f'<p>{st["flows"]} requests captured by mitmproxy and grouped into <b>{st["endpoints"]}</b> endpoints. '
             f'North-south traffic came through the reverse proxy in front of the gateway, east-west traffic through '
             f'the proxy the services use to call each other. Bodies are reduced to field names and types at capture '
             f'time, so tokens, emails and card numbers never reach the disk.</p>')
    return intro + f'<div class="scroll"><table><thead><tr>{th}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def _spec_panel(d):
    oa = d["openapi"]
    if not oa:
        return "<p class='muted'>No OpenAPI file.</p>"
    blocks = []
    for s in oa["records"]:
        rows = []
        for o in s["operations"]:
            auth_tone = {"required": "ok", "optional": "warn", "none": "warn"}[o["auth_declared"]]
            body = ", ".join(f"{k}: {v}" for k, v in ((o["request_body"] or {}).get("fields") or {}).items())
            rows.append([
                f'<span class="method">{E(o["method"])}</span>',
                f'<span class="mono">{E(o["path"])}</span>' + (" " + _chip("deprecated", "warn") if o["deprecated"] else ""),
                _chip("auth " + o["auth_declared"], auth_tone),
                f'<span class="mono">{E(body)}</span>' if body else '<span class="muted">–</span>',
                f'<span class="mono">{E(", ".join(o["responses"]))}</span>',
            ])
        origin = _chip("live: " + s["location"], "ok") if s["origin"] == "live" else _chip("file: " + Path(s["location"]).name, "info")
        blocks.append(
            f'<div style="display:grid;gap:8px"><h3>{E(s["service"])} <span class="muted mono">'
            f'OpenAPI {E(s["spec_version"])} · api v{E(str(s["api_version"]))}</span></h3>'
            f'<div>{origin} {"".join(_chip("scheme: " + k + " (" + v.get("type", "") + ")") for k, v in s["security_schemes"].items())}</div>'
            + _table(["Method", "Path", "Declared auth", "Request body fields", "Responses"], rows) + "</div>")
    missing = oa["stats"].get("services_without_live_spec", [])
    probe_rows = [[E(p["service"]), f'<span class="mono">{E(p["url"])}</span>',
                   _chip(p["result"], "ok" if p["result"] == "spec" else "info")] for p in oa.get("probe_log", [])]
    intro = (f'<p>The prober tried {len(oa.get("probe_log", []))} well-known spec URLs and also read spec files from the repo. '
             + (f'No live spec was found for {", ".join("<b>" + E(m) + "</b>" for m in missing)}.' if missing else "")
             + '</p>')
    return intro + "".join(blocks) + (
        f'<details><summary>Probe log ({len(probe_rows)} requests)</summary>'
        + _table(["Service", "URL", "Result"], probe_rows) + "</details>")


def _infra_panel(d):
    inf = d["infrastructure"]
    if not inf:
        return "<p class='muted'>No infrastructure file.</p>"
    exp = defaultdict(set)
    for e in _recs(inf, "exposure"):
        exp[e["workload"]].add(e["level"])
    wrows = []
    for w in _recs(inf, "workload"):
        for c in w["containers"]:
            sc = c["security_context"]
            flags = []
            if sc.get("privileged"):
                flags.append(_chip("privileged", "crit"))
            if sc.get("runAsUser") == 0:
                flags.append(_chip("runs as root", "crit"))
            if sc.get("runAsNonRoot"):
                flags.append(_chip("non-root", "ok"))
            if not c["resources"]["limits"]:
                flags.append(_chip("no limits", "warn"))
            if c["image_tag"].startswith("latest"):
                flags.append(_chip("tag latest", "warn"))
            env = []
            for e in c["env"]:
                if e["source"] == "plaintext" and e["sensitive_name"]:
                    env.append(_chip(f'{e["name"]} plaintext', "crit", "value not copied into the output"))
                elif e["source"] == "secretRef":
                    env.append(_chip(f'{e["name"]} from Secret', "ok"))
                elif e.get("references_service"):
                    env.append(_chip(f'{e["name"]} → {e["references_service"]}', "info"))
            level = "internet" if "internet" in exp[w["name"]] else "node" if "node" in exp[w["name"]] else "internal"
            wrows.append([
                f'<b>{E(w["name"])}</b><br><span class="muted mono">{E(c["image"])}</span>',
                _chip(level, {"internet": "crit", "node": "warn", "internal": "ok"}[level]),
                "".join(flags) or '<span class="muted">–</span>',
                "".join(env) or '<span class="muted">–</span>',
                _chip("yes", "ok") if w["network_policies"] else _chip("none", "warn"),
            ])
    svc_rows = [[E(s["name"]), _chip(s["type"], "warn" if s["type"] != "ClusterIP" else "info"),
                 f'<span class="mono">{E(", ".join(str(p.get("port")) + (" → node " + str(p["nodePort"]) if p.get("nodePort") else "") for p in s["ports"]))}</span>',
                 E(", ".join(s["selects_workloads"]) or "–")] for s in _recs(inf, "service")]
    ing_rows = [[E(i["host"] + i["path"]), E(i["backend_service"] or "?"), _chip("TLS", "ok") if i["tls"] else _chip("no TLS", "warn")]
                for i in _recs(inf, "ingress")]
    sec_rows = [[E(s["name"]), f'<span class="mono">{E(", ".join(s["keys"]))}</span>'] for s in _recs(inf, "secret")]
    st = inf["stats"]
    intro = (f'<p>{st["files"]} manifest files parsed: {st["workloads"]} workloads, {st["services"]} services, '
             f'{st["ingress_paths"]} ingress path(s), {st["gateway_routes"]} gateway routes, {st["network_policies"]} network '
             f'policy. Secret values and sensitive env values are never copied; URLs in env vars are kept because they '
             f'show dependencies.</p>')
    return (intro
            + _table(["Workload", "Reachable from", "Container flags", "Env (names only)", "Network policy"], wrows)
            + '<div class="grid2"><div style="display:grid;gap:8px"><h3>Services</h3>'
            + _table(["Name", "Type", "Ports", "Selects"], svc_rows) + '</div>'
            + '<div style="display:grid;gap:8px"><h3>Ingress</h3>' + _table(["Host + path", "Backend", "TLS"], ing_rows)
            + '<h3>Secrets</h3>' + _table(["Name", "Keys (no values)"], sec_rows) + '</div></div>')


def _trace_panel(d):
    cc = d["callchain"]
    if not cc:
        return "<p class='muted'>No call-chain file.</p>"
    edge_rows = []
    for e in _recs(cc, "edge"):
        ops = "<br>".join(f'<span class="mono">{E(o["operation"])}</span> <span class="muted">×{o["count"]}'
                          f'{", p50 " + str(o["p50_ms"]) + " ms" if o["p50_ms"] is not None else ""}</span>'
                          for o in e["operations"])
        edge_rows.append([f'<b>{E(e["from"])}</b>', f'<b>{E(e["to"])}</b>', str(e["calls"]), ops])
    chains = []
    for c in _recs(cc, "call_chain")[:8]:
        lines = []
        for h in c["hops"]:
            pad = "&nbsp;&nbsp;&nbsp;&nbsp;" * h["depth"] + ("└─ " if h["depth"] else "")
            lines.append(f'{pad}<span class="svc">{E(h["service"])}</span> {E(h["operation"])}')
        chains.append(f'<div class="chain"><span class="n">{c["traces"]} trace(s)</span><br>{"<br>".join(lines)}</div>')
    entries = [[E(e["service"]), f'<span class="mono">{E(e["operation"])}</span>', str(e["traces"]), E(e["note"])]
               for e in _recs(cc, "entrypoint")]
    st = cc["stats"]
    return (f'<p>{st["spans"]} spans from {st["traces"]} traces. Each edge is a real call seen in a trace, so this is the '
            f'dependency graph as it runs, not as anyone drew it. Deepest chain: {st["max_chain_depth"]} services.</p>'
            + '<h3>Service-to-service edges</h3>' + _table(["Caller", "Callee", "Calls", "Operations used"], edge_rows, (2,))
            + '<h3>Where traces start</h3>' + _table(["Service", "Operation", "Traces", "Note"], entries, (2,))
            + '<h3>Most common call chains</h3><div class="grid2">' + "".join(chains) + "</div>")


def build_report(raw_dir, out_path, fragment: bool = False) -> str:
    raw_dir, out_path = Path(raw_dir), Path(out_path)
    d = _load(raw_dir)
    m = d["manifest"]
    target = m.get("target") or "target"

    # source rows
    def nums(name):
        doc = d[name]
        if not doc:
            return "<span>not run</span>"
        s = doc["stats"]
        pick = {
            "runtime_traffic": [("flows", s.get("flows")), ("endpoints", s.get("endpoints")), ("services", s.get("services"))],
            "openapi": [("specs", s.get("specs")), ("documented operations", s.get("operations")),
                        ("services with no live spec", len(s.get("services_without_live_spec", [])))],
            "infrastructure": [("workloads", s.get("workloads")), ("gateway routes", s.get("gateway_routes")),
                               ("internet-reachable", len(s.get("internet_exposed_workloads", [])))],
            "callchain": [("traces", s.get("traces")), ("service edges", s.get("edges")),
                          ("distinct chains", s.get("distinct_call_chains"))],
        }[name]
        return "".join(f"<span><b>{v}</b> {k}</span>" for k, v in pick)

    src_rows = []
    for name, tool, label, c in SOURCES:
        doc = d[name]
        warns = "".join(f"<div>{E(w)}</div>" for w in (doc or {}).get("warnings", []))
        src_rows.append(
            f'<div class="src c-{c}"><div class="tool"><i></i>{tool}</div>'
            f'<div class="what"><b>{label}</b><div class="nums">{nums(name)}</div>'
            f'{f"<div class=warnings>{warns}</div>" if warns else ""}</div>'
            f'<div class="time">{(doc or {}).get("duration_ms", "–")} ms<br>{len((doc or {}).get("records", []))} records</div></div>')

    cov, gateways = _coverage(d)
    n_warn = sum(1 for r in cov if r["status"][1] == "warn")
    n_info = sum(1 for r in cov if r["status"][1] == "info")
    cov_body, last = [], None
    for r in cov:
        if r["service"] != last:
            cov_body.append(f'<tr class="svc-group"><td colspan="6">{E(r["service"])}</td></tr>')
            last = r["service"]
        cov_body.append(
            "<tr>"
            f'<td><span class="method">{E(r["method"])}</span></td>'
            f'<td class="path">{E(r["path"])}{" " + _chip("deprecated", "warn") if r["deprecated"] else ""}</td>'
            f'<td>{"".join(_chip(s, "info") for s in r["spec"]) or "<span class=muted>–</span>"}</td>'
            f'<td class="num">{r["traffic"] or "–"}</td><td class="num">{r["trace"] or "–"}</td>'
            f'<td>{_chip(*r["status"])}</td></tr>')
    cov_table = ('<div class="scroll"><table><thead><tr><th>Method</th><th>Path</th><th>In spec</th>'
                 '<th class="num">Traffic hits</th><th class="num">Trace spans</th><th>Across sources</th></tr></thead>'
                 f'<tbody>{"".join(cov_body)}</tbody></table></div>')

    groutes, unrouted = _gateway_rows(d, gateways)
    g_rows = []
    for r in groutes:
        hits = sum(p["hits"] for p in r["paths"])
        missing = sum(p["auth"]["authorization_header_missing"] for p in r["paths"])
        g_rows.append([f'<span class="mono">{E(r["match_prefix"])}/**</span>', E(r["upstream_service"]),
                       _chip("auth " + r["auth"], "ok" if r["auth"] == "required" else "warn"),
                       str(hits), str(missing) if missing else "–",
                       "<br>".join(f'<span class="mono">{E(p["method"])} {E(p["path_template"])}</span>' for p in r["paths"])])
    for p in unrouted:
        g_rows.append([f'<span class="mono">{E(p["path_template"])}</span>', '<span class="muted">gateway itself</span>',
                       _chip("not in route config", "warn"), str(p["hits"]),
                       str(p["auth"]["authorization_header_missing"]) or "–",
                       f'<span class="mono">{E(p["method"])} {E(p["path_template"])}</span>'])

    files = []
    for name, *_ in SOURCES:
        s = m.get("sources", {}).get(name, {})
        files.append([E(Path(s.get("file", name + ".json")).name), _chip(s.get("status", "missing"),
                      "ok" if s.get("status") == "ok" else "crit"),
                      str(s.get("records", "–")), f'<span class="sha">{E(s.get("sha256", ""))}</span>'])

    tabs = [("p-traffic", "traffic", "Runtime traffic"), ("p-spec", "spec", "OpenAPI"),
            ("p-infra", "infra", "Infrastructure"), ("p-trace", "trace", "Call chains")]
    tab_html = "".join(f'<button class="tab c-{c}" type="button" role="tab" data-panel="{pid}" id="t-{pid}">'
                       f'<i></i>{label}</button>' for pid, c, label in tabs)
    panels = {
        "p-traffic": _traffic_panel(d), "p-spec": _spec_panel(d),
        "p-infra": _infra_panel(d), "p-trace": _trace_panel(d),
    }
    raw_details = "".join(
        f'<details><summary>{name}.json</summary><pre>{E(json.dumps(d[name], indent=2)[:60000])}</pre></details>'
        for name, *_ in SOURCES if d[name])

    body = f"""
<title>{E(target)} Extractor Run</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=JetBrains+Mono:wght@400;600;700&family=Public+Sans:wght@400;600;700&display=swap">
<style>{CSS}</style>
<div class="wrap">
  <header class="head">
    <div class="eyebrow">Automatic API Security Design Review · Phase 1</div>
    <h1>{E(target)}: what the four extractors found</h1>
    <p class="muted">Raw API data collected from a running microservice system, before any normalization or rule
    checks. Phases 2 to 4 read the JSON files listed at the bottom of this page.</p>
    <div class="meta"><span>run {E(m.get("run_id", "?"))}</span><span>{E(m.get("started_at", ""))}</span>
    <span>total {m.get("total_duration_ms", "–")} ms</span><span>schema {E(m.get("schema", ""))}</span></div>
    <div class="pipe" aria-label="Pipeline progress">
      <div class="stage now"><b>1 · Extractor</b><span>this page</span></div>
      <div class="stage"><b>2 · API Normalizer</b><span>next: merge into EUJF</span></div>
      <div class="stage"><b>3 · Analysis &amp; risk</b><span>rule engine, threat graph</span></div>
      <div class="stage"><b>4 · Output</b><span>dashboard</span></div>
    </div>
  </header>

  <section aria-labelledby="h-src">
    <h2 id="h-src">Four discovery sources</h2>
    <div class="sources">{"".join(src_rows)}</div>
  </section>

  <section aria-labelledby="h-map">
    <h2 id="h-map">Service map</h2>
    <p class="muted">Nodes come from the Kubernetes manifests, arrows from traces. The coloured bar on each service shows how far
    it can be reached from: red internet, amber cluster nodes, green internal only.</p>
    <div class="scroll">{_service_map_svg(d)}</div>
    <div class="legend">
      <span class="c-trace"><i style="--c:var(--src-trace)"></i>call seen in traces</span>
      <span><i style="--c:var(--crit)"></i>public via Ingress</span>
      <span><i class="dash" style="--c:var(--warn)"></i>NodePort on every node</span>
      <span><i class="dash" style="--c:var(--muted)"></i>caller with no trace upstream</span>
    </div>
  </section>

  <section aria-labelledby="h-cov">
    <h2 id="h-cov">Endpoint coverage across sources</h2>
    <p class="muted">Each backend endpoint, matched by service, method and path shape. A quick join to show why four sources
    matter; Phase 2 does this merge properly and Phase 3 decides what is a finding.</p>
    <div class="counts">
      <div class="count"><b>{len(cov)}</b><span>backend endpoints</span></div>
      <div class="count"><b style="color:var(--warn)">{n_warn}</b><span>observed, in no spec</span></div>
      <div class="count"><b>{n_info}</b><span>documented, never observed</span></div>
    </div>
    {cov_table}
    <h3>Gateway routes vs. traffic</h3>
    {_table(["Route", "Upstream", "Gateway auth", "Hits", "No token", "Paths seen"], g_rows, (3, 4))}
  </section>

  <section aria-labelledby="h-detail">
    <h2 id="h-detail">Source detail</h2>
    <div class="tabs" role="tablist">{tab_html}</div>
    {"".join(f'<div class="panel" id="{pid}" role="tabpanel" aria-labelledby="t-{pid}">{panels[pid]}</div>' for pid, *_ in tabs)}
  </section>

  <section aria-labelledby="h-files">
    <h2 id="h-files">Raw API data handed to Phase 2</h2>
    <p class="muted">Same envelope in every file (<code>schema, source, run_id, stats, warnings, records</code>).
    The full contract is in <code>docs/RAW_DATA_CONTRACT.md</code>.</p>
    {_table(["File", "Status", "Records", "SHA-256"], files, (2,), "files")}
    {raw_details}
  </section>
</div>
<script>{JS}</script>
"""
    page = body if fragment else (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>'
        + body + "</body></html>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")
    return str(out_path)
