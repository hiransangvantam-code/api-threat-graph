"""
Phase 4 - OUTPUT: threat graph with propagated risk  ->  output/dashboard.html

One self-contained HTML page (no server, works offline) with the four outputs
from Fig. 1, plus what the professor asked for:

    API overview        inventory of every endpoint and service, from all four sources
    Risk summary        attack-path risk, severity counts, generated insights
    Top vulnerability   ranked findings; each one opens to evidence, score explanation,
                        references (OWASP / CWE / ATT&CK / NIST) and the mitigation
    Trend & insight     risk across runs (before / after fixes)
    + Attack paths, the interactive threat graph, the mitigation plan, the rule catalog
"""
from __future__ import annotations

import html
import json
import math
from collections import defaultdict
from pathlib import Path

from extractor.report import CSS as BASE_CSS
from .rules import RISKS, catalog

E = html.escape
SEVS = ["critical", "high", "medium", "low"]
TYPE_ORDER = ["Actor", "API", "Endpoint", "Dependency", "Vulnerability", "Risk"]

OWASP_SLUG = {
    "API1": "0xa1-broken-object-level-authorization", "API2": "0xa2-broken-authentication",
    "API3": "0xa3-broken-object-property-level-authorization", "API4": "0xa4-unrestricted-resource-consumption",
    "API5": "0xa5-broken-function-level-authorization", "API6": "0xa6-unrestricted-access-to-sensitive-business-flows",
    "API7": "0xa7-server-side-request-forgery", "API8": "0xa8-security-misconfiguration",
    "API9": "0xa9-improper-inventory-management", "API10": "0xaa-unsafe-consumption-of-apis",
}
NIST_URL = {
    "SP 800-204": "https://csrc.nist.gov/pubs/sp/800/204/final",
    "SP 800-207": "https://csrc.nist.gov/pubs/sp/800/207/final",
    "SP 800-190": "https://csrc.nist.gov/pubs/sp/800/190/final",
    "SP 800-95": "https://csrc.nist.gov/pubs/sp/800/95/final",
    "SP 800-63B": "https://pages.nist.gov/800-63-3/sp800-63b.html",
}


def _owasp_link(o: str) -> str:
    key = o.split(":")[0]
    return f'<a href="https://owasp.org/API-Security/editions/2023/en/{OWASP_SLUG.get(key, "")}/" target="_blank" rel="noopener">{E(o)}</a>'


def _cwe_link(c: str) -> str:
    return f'<a href="https://cwe.mitre.org/data/definitions/{c.split("-")[1]}.html" target="_blank" rel="noopener">{E(c)}</a>'


def _attack_link(t: str) -> str:
    return f'<a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/" target="_blank" rel="noopener">{E(t)}</a>'


def _nist_link(n: str) -> str:
    u = NIST_URL.get(n)
    return f'<a href="{u}" target="_blank" rel="noopener">NIST {E(n)}</a>' if u else f"NIST {E(n)}"


def _sev(s: str, text: str | None = None) -> str:
    return f'<span class="sev sev-{s}">{E(text or s)}</span>'


def _chip(text, tone="info"):
    return f'<span class="chip {tone}">{E(str(text))}</span>'


# ---------------------------------------------------------------------------
# threat graph (layered SVG, layout computed here so it works offline)
# ---------------------------------------------------------------------------
def _graph_svg(analysis: dict) -> str:
    nodes = {n["id"]: n for n in analysis["graph"]["nodes"]}
    edges = [e for e in analysis["graph"]["edges"] if e["rel"] not in ("runs_on",)]
    cols: dict[str, list[str]] = defaultdict(list)
    for n in nodes.values():
        cols[n["type"]].append(n["id"])

    # ordering to reduce crossings
    api_order = sorted(cols["API"], key=lambda i: (nodes[i]["props"].get("role") != "gateway", nodes[i]["label"]))
    api_rank = {a: k for k, a in enumerate(api_order)}
    svc_of = {n["id"]: f"svc:{n['props'].get('service')}" for n in nodes.values() if n["type"] == "Endpoint"}
    ep_order = sorted(cols["Endpoint"], key=lambda i: (api_rank.get(svc_of[i], 99), nodes[i]["label"].split(" ", 1)[1], nodes[i]["label"]))
    order = {"Actor": sorted(cols["Actor"], key=lambda i: i != "actor:internet"), "API": api_order, "Endpoint": ep_order}
    pos_rank = {i: k for k, i in enumerate(api_order)} | {i: k for k, i in enumerate(ep_order)}

    srcs = defaultdict(list)
    for e in edges:
        srcs[e["dst"]].append(e["src"])

    def mean_rank(i, scale):
        rs = [pos_rank[s] / max(1, len(scale)) for s in srcs[i] if s in pos_rank]
        return sum(rs) / len(rs) if rs else 2

    order["Dependency"] = sorted(cols["Dependency"], key=lambda i: (mean_rank(i, ep_order), nodes[i]["label"]))
    order["Vulnerability"] = sorted(cols["Vulnerability"], key=lambda i: (mean_rank(i, ep_order), -nodes[i]["props"].get("score", 0)))
    for k, i in enumerate(order["Vulnerability"]):
        pos_rank[i] = k
    order["Risk"] = sorted(cols["Risk"], key=lambda i: mean_rank(i, order["Vulnerability"]))

    colw, nodew, rowh, top = 180, 160, 27, 40
    tallest = max(len(v) for v in order.values())
    H = tallest * rowh + top + 20
    W = len(TYPE_ORDER) * colw
    xy = {}
    for c, t in enumerate(TYPE_ORDER):
        ids = order.get(t, [])
        span = H - top - 20
        step = span / max(1, len(ids))
        for k, i in enumerate(ids):
            xy[i] = (12 + c * colw, top + step * k + step / 2 - 11)

    out = []
    for c, t in enumerate(TYPE_ORDER):
        out.append(f'<text class="gcol" x="{12 + c * colw}" y="20">{t.upper()}</text>')
    W = 12 + (len(TYPE_ORDER) - 1) * colw + nodew + 8
    for e in edges:
        if e["src"] not in xy or e["dst"] not in xy:
            continue
        (x1, y1), (x2, y2) = xy[e["src"]], xy[e["dst"]]
        x1 += nodew
        y1 += 11
        y2 += 11
        if x2 <= x1:  # same column (calls / depends_on): arc out to the right
            path = f"M{x1},{y1} C{x1 + 50},{y1} {x1 + 50},{y2} {x2 + nodew},{y2}"
        else:
            mx = (x1 + x2) / 2
            path = f"M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}"
        out.append(f'<path class="ge r-{e["rel"]}" data-s="{E(e["src"])}" data-t="{E(e["dst"])}" d="{path}"/>')
    for i, n in nodes.items():
        if i not in xy:
            continue
        x, y = xy[i]
        prop = n.get("propagated_risk", 0) or 0
        sev = "critical" if prop >= 20 else "high" if prop >= 12 else "medium" if prop >= 6 else "low" if prop > 0 else "none"
        label = n["label"]
        limit = 20 if prop else 24  # leave room for the score on the right
        if len(label) > limit:
            label = label[:limit - 1] + "…"
        score = f'<text class="gscore" x="{x + nodew - 6}" y="{y + 15}" text-anchor="end">{prop:g}</text>' if prop else ""
        out.append(f'<g class="gn t-{n["type"]} risk-{sev}" data-id="{E(i)}" tabindex="0"><title>{E(n["label"])}</title>'
                   f'<rect x="{x}" y="{y}" width="{nodew}" height="22" rx="4"/>'
                   f'<circle cx="{x + 10}" cy="{y + 11}" r="4"/>'
                   f'<text x="{x + 19}" y="{y + 15}">{E(label)}</text>{score}</g>')
    return (f'<svg class="tgraph" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
            f'aria-label="Threat graph">{"".join(out)}</svg>')


def _trend_svg(history: list[dict], current: str) -> str:
    if not history:
        return "<p class='muted'>No history yet.</p>"
    w, h, pl, pr, pt, pb = 640, 230, 56, 64, 30, 52
    n = len(history)
    ymax = max(r["total_path_risk"] for r in history) or 1
    nice = 10 ** math.floor(math.log10(ymax))
    ymax = math.ceil(ymax / nice) * nice

    def X(i):
        return pl + (w - pl - pr) * (i / (n - 1) if n > 1 else 0.5)

    def Y(v):
        return pt + (h - pt - pb) * (1 - v / ymax)

    g = []
    for k in range(5):
        v = ymax * k / 4
        g.append(f'<line class="grid" x1="{pl}" x2="{w - pr}" y1="{Y(v):.1f}" y2="{Y(v):.1f}"/>'
                 f'<text class="axis" x="{pl - 8}" y="{Y(v) + 4:.1f}" text-anchor="end">{v:g}</text>')
    pts = " ".join(f"{X(i):.1f},{Y(r['total_path_risk']):.1f}" for i, r in enumerate(history))
    area = f"{X(0):.1f},{Y(0):.1f} {pts} {X(n - 1):.1f},{Y(0):.1f}"
    g.append(f'<polygon class="tarea" points="{area}"/><polyline class="tline" points="{pts}"/>')
    for i, r in enumerate(history):
        cur = r["run_id"] == current
        g.append(f'<circle class="tdot{" cur" if cur else ""}" cx="{X(i):.1f}" cy="{Y(r["total_path_risk"]):.1f}" r="{6 if cur else 4}">'
                 f'<title>{E(r["run_id"])}: {r["total_path_risk"]}</title></circle>'
                 f'<text class="tval" x="{X(i):.1f}" y="{Y(r["total_path_risk"]) - 10:.1f}" text-anchor="middle">{r["total_path_risk"]:g}</text>'
                 f'<text class="axis" x="{X(i):.1f}" y="{h - pb + 18}" text-anchor="middle">{E(r.get("label") or "run")}</text>'
                 f'<text class="axis dim" x="{X(i):.1f}" y="{h - pb + 33}" text-anchor="middle">{E(r["run_id"][4:8] + " " + r["run_id"][9:13])}</text>')
    return f'<svg class="trend" viewBox="0 0 {w} {h}" width="100%" style="max-width:{w}px" role="img" aria-label="Attack-path risk per run">{"".join(g)}</svg>'


# ---------------------------------------------------------------------------
def _insights(analysis: dict, eujf: dict, history: list[dict]) -> list[str]:
    s, plan, f = analysis["summary"], analysis["mitigation_plan"], analysis["findings"]
    out = []
    if plan["steps"]:
        top = plan["steps"][0]
        out.append(f"The single most valuable fix is <b>{E(top['title'])}</b>: it removes "
                   f"{top['cumulative_reduction_pct']}% of attack-path risk on its own.")
    if plan["fixes_for_70pct"]:
        out.append(f"<b>{plan['fixes_for_70pct']}</b> of {len(plan['steps'])} remediation actions remove 70% of the "
                   f"attack-path risk; {plan['fixes_for_90pct'] or len(plan['steps'])} remove 90%.")
    shadow = [e for e in eujf["endpoints"] if e["inventory_status"] == "shadow"]
    if shadow:
        risky = [e for e in shadow if any(x["target"] == e["id"] and x["severity"] in ("critical", "high") for x in f)]
        out.append(f"<b>{len(shadow)}</b> of {len(eujf['endpoints'])} endpoints are in no API spec; {len(risky)} of them carry "
                   "critical or high findings. A spec-only review would have missed them.")
    multi = [x for x in f if len(x["sources"]) >= 2]
    if f:
        out.append(f"{len(multi)} of {len(f)} findings are backed by two or more independent sources "
                   "(spec, traffic, manifests, traces).")
    internet = [p for p in analysis["attack_paths"] if p["entry"] == "actor:internet" and p["severity"] == "critical"]
    if internet:
        out.append(f"<b>{len(internet)}</b> critical attack paths start from the internet. The shortest has "
                   f"{min(p['hops'] for p in internet)} hops.")
    svc = max((n for n in analysis["graph"]["nodes"] if n["type"] == "API"), key=lambda n: n.get("propagated_risk", 0), default=None)
    if svc:
        out.append(f"Highest propagated risk: <b>{E(svc['label'])}</b> ({svc.get('propagated_risk', 0):g}/25), "
                   "the service whose exposure leads to the worst outcomes.")
    if len(history) >= 2 and history[0]["total_path_risk"]:
        a, b = history[0], history[-1]
        d = round(100 * (1 - b["total_path_risk"] / a["total_path_risk"]), 1)
        word = "fell" if d > 0 else "rose"
        out.append(f"Across {len(history)} stored runs, attack-path risk {word} <b>{abs(d)}%</b>, from {a['total_path_risk']:g} "
                   f"({E(a.get('label') or a['run_id'])}) to {b['total_path_risk']:g} ({E(b.get('label') or b['run_id'])}).")
    return out


CSS = BASE_CSS + """
.sev{display:inline-block;font:700 11px/1.7 var(--f-mono);letter-spacing:.04em;text-transform:uppercase;padding:0 7px;border-radius:3px;white-space:nowrap}
.sev-critical{background:var(--crit);color:var(--surface)}
.sev-high{background:var(--sev-high-soft);color:var(--sev-high)}
.sev-medium{background:var(--warn-soft);color:var(--warn)}
.sev-low{background:var(--info-soft);color:var(--info)}
:root{--sev-high:#c2410c;--sev-high-soft:#fde7d9;--t-actor:#5a6675;--t-api:#2563eb;--t-endpoint:#2c7a4b;--t-dep:#b7791f;--t-vuln:#c2410c;--t-risk:#be123c}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--sev-high:#fb923c;--sev-high-soft:#3b2212;--t-actor:#97a3b2;--t-api:#7aa7ff;--t-endpoint:#5fcf8a;--t-dep:#f0b04f;--t-vuln:#fb923c;--t-risk:#fb7185}}
:root[data-theme="dark"]{--sev-high:#fb923c;--sev-high-soft:#3b2212;--t-actor:#97a3b2;--t-api:#7aa7ff;--t-endpoint:#5fcf8a;--t-dep:#f0b04f;--t-vuln:#fb923c;--t-risk:#fb7185}
.pipe .stage.done{border-color:var(--ok)}
.pipe .stage.done b::after{content:" ✓";color:var(--ok)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.kpi{border:1px solid var(--line);border-radius:6px;background:var(--surface);padding:10px 14px;display:grid;gap:2px}
.kpi b{font:700 26px/1.1 var(--f-display);font-variant-numeric:tabular-nums}
.kpi span{font-size:12.5px;color:var(--muted)}
.sevbar{display:flex;height:12px;border-radius:3px;overflow:hidden;background:var(--surface-2)}
.sevbar i{display:block}
.insights{display:grid;gap:8px;margin:0;padding-left:18px;max-width:90ch}
.insights li{line-height:1.5}
.filters{display:flex;flex-wrap:wrap;gap:6px}
.filter{font:600 12.5px var(--f-body);border:1px solid var(--line);background:var(--surface);color:var(--fg);border-radius:999px;padding:4px 12px;cursor:pointer}
.filter[aria-pressed="true"]{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.findings tr.frow{cursor:pointer}
.findings tr.frow:hover td{background:var(--surface-2)}
.findings tr.fdetail td{background:var(--surface-2);padding:14px 16px}
.fbody{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:16px 28px;font-size:13.5px}
.fbody h4{margin:0 0 4px;font:600 11px var(--f-mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.fbody ul,.fbody ol{margin:0;padding-left:18px;display:grid;gap:3px}
.fbody pre{border:1px solid var(--line);border-radius:4px;max-height:none}
.fbody a{color:var(--src-infra)}
.refs{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:13px}
.score{font:700 13px var(--f-mono);font-variant-numeric:tabular-nums}
.paths{display:grid;gap:8px}
.apath{border:1px solid var(--line);border-radius:6px;background:var(--surface);padding:10px 12px;display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 14px;align-items:center;cursor:pointer;text-align:left;color:var(--fg);font:inherit}
.apath:hover,.apath[aria-pressed="true"]{border-color:var(--accent)}
.apath .apcr{font:700 20px var(--f-display);font-variant-numeric:tabular-nums;min-width:52px}
.hops{display:flex;flex-wrap:wrap;align-items:center;gap:4px;font-size:12.5px;min-width:0}
.hop{border-radius:3px;padding:1px 6px;background:var(--surface-2);border-left:3px solid var(--c)}
.hop.t-Actor{--c:var(--t-actor)}.hop.t-API{--c:var(--t-api)}.hop.t-Endpoint{--c:var(--t-endpoint)}.hop.t-Vulnerability{--c:var(--t-vuln)}.hop.t-Risk{--c:var(--t-risk)}
.arrow{color:var(--muted)}
.graphwrap{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:12px}
@media (max-width:900px){.graphwrap{grid-template-columns:1fr}}
.tgraph{display:block;font-family:var(--f-body)}
.tgraph .gcol{font:600 11px var(--f-mono);letter-spacing:.08em;fill:var(--muted)}
.tgraph .ge{fill:none;stroke:var(--line);stroke-width:1.1;opacity:.9}
.tgraph .ge.r-has_vuln{stroke:var(--t-vuln);opacity:.35}
.tgraph .ge.r-leads_to{stroke:var(--t-risk);opacity:.3}
.tgraph .ge.r-calls{stroke:var(--src-trace);stroke-dasharray:3 3}
.tgraph .ge.r-reaches{stroke:var(--crit);opacity:.5}
.tgraph .ge.hl{stroke:var(--accent);stroke-width:2.4;opacity:1}
.tgraph .gn{cursor:pointer}
.tgraph .gn rect{fill:var(--surface-2);stroke:var(--line)}
.tgraph .gn text{font-size:11.5px;fill:var(--fg)}
.tgraph .gn .gscore{font:700 10.5px var(--f-mono)}
.tgraph .gn circle{stroke:none}
.tgraph .t-Actor circle{fill:var(--t-actor)}.tgraph .t-API circle{fill:var(--t-api)}.tgraph .t-Endpoint circle{fill:var(--t-endpoint)}
.tgraph .t-Dependency circle{fill:var(--t-dep)}.tgraph .t-Vulnerability circle{fill:var(--t-vuln)}.tgraph .t-Risk circle{fill:var(--t-risk)}
.tgraph .risk-critical rect{stroke:var(--crit);stroke-width:1.6}.tgraph .risk-critical .gscore{fill:var(--crit)}
.tgraph .risk-high rect{stroke:var(--sev-high);stroke-width:1.4}.tgraph .risk-high .gscore{fill:var(--sev-high)}
.tgraph .risk-medium .gscore{fill:var(--warn)}.tgraph .risk-low .gscore{fill:var(--muted)}
.tgraph .gn.sel rect{fill:var(--accent-soft);stroke:var(--accent);stroke-width:2}
.tgraph .gn.dim{opacity:.25}
.tgraph .gn:focus-visible rect{stroke:var(--accent);stroke-width:2.5}
.gpanel{position:sticky;top:calc(env(safe-area-inset-top,0px) + 8px);z-index:2;border:1px solid var(--line);border-radius:8px;background:var(--surface);padding:10px 14px;font-size:13px;display:grid;gap:6px;max-height:260px;overflow:auto;box-shadow:0 6px 18px -10px rgba(0,0,0,.35)}
.gpanel dl{grid-template-columns:auto 1fr}
.gpanel h3{font-size:14px}
.gpanel dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:3px 10px}
.gpanel dt{color:var(--muted)}
.gpanel dd{margin:0;word-break:break-word}
.tlegend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12.5px;color:var(--muted)}
.tlegend span{display:inline-flex;align-items:center;gap:6px}
.tlegend i{width:10px;height:10px;border-radius:50%;background:var(--c)}
.plan{display:grid;gap:6px}
.step{display:grid;grid-template-columns:28px minmax(0,1fr) 170px;gap:12px;align-items:center;border-bottom:1px solid var(--line);padding:8px 0}
.step:last-child{border-bottom:0}
.step .n{font:700 13px var(--f-mono);color:var(--muted)}
.step .t{display:grid;gap:2px;min-width:0}
.step .t small{color:var(--muted)}
.cum{display:grid;gap:3px;font:12px var(--f-mono);font-variant-numeric:tabular-nums}
.cum .bar{height:6px;background:var(--surface-2);border-radius:3px;overflow:hidden}
.cum .bar i{display:block;height:100%;background:var(--ok)}
@media (max-width:640px){.step{grid-template-columns:24px minmax(0,1fr)}.step .cum{grid-column:2}}
.trend .grid{stroke:var(--line)}
.trend .axis{font:11px var(--f-mono);fill:var(--muted)}
.trend .axis.dim{opacity:.7}
.trend .tline{fill:none;stroke:var(--accent);stroke-width:2.2}
.trend .tarea{fill:var(--accent-soft);opacity:.7}
.trend .tdot{fill:var(--surface);stroke:var(--accent);stroke-width:2}
.trend .tdot.cur{fill:var(--accent)}
.trend .tval{font:700 11.5px var(--f-mono);fill:var(--fg)}
.sources-mini{display:flex;gap:3px}
.sources-mini i{width:9px;height:9px;border-radius:2px;background:var(--c);display:inline-block}
.sources-mini i.off{background:var(--surface-2);outline:1px solid var(--line)}
.inv td.path{min-width:150px}
.wrap a{color:var(--t-api)}
"""

JS = r"""
(function(){
  // ---- findings: filter + expand
  var rows=[].slice.call(document.querySelectorAll('tr.frow'));
  var active={sev:'all',grp:'all'},all=false;var btn=document.getElementById('showall');
  function apply(){var shown=0;rows.forEach(function(r){var ok=(active.sev==='all'||r.dataset.sev===active.sev)&&(active.grp==='all'||r.dataset.grp===active.grp);
    var filtering=active.sev!=='all'||active.grp!=='all';if(ok&&!all&&!filtering&&shown>=12)ok=false;if(ok)shown++;
    r.hidden=!ok;var d=document.getElementById('d-'+r.dataset.id);if(!ok&&d)d.hidden=true;});}
  if(btn)btn.addEventListener('click',function(){all=!all;btn.textContent=all?'Show top 12':'Show all '+rows.length+' findings';btn.setAttribute('aria-expanded',all);apply();});
  apply();
  document.querySelectorAll('.filter[data-k]').forEach(function(b){b.addEventListener('click',function(){
    var k=b.dataset.k;active[k]=b.dataset.v;document.querySelectorAll('.filter[data-k="'+k+'"]').forEach(function(x){x.setAttribute('aria-pressed',x===b)});apply();});});
  rows.forEach(function(r){function t(){var d=document.getElementById('d-'+r.dataset.id);d.hidden=!d.hidden;r.setAttribute('aria-expanded',!d.hidden);}
    r.addEventListener('click',t);r.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();t();}});});
  // ---- graph
  var data=JSON.parse(document.getElementById('gdata').textContent);
  var edges=[].slice.call(document.querySelectorAll('.tgraph .ge'));
  var gnodes=[].slice.call(document.querySelectorAll('.tgraph .gn'));
  var panel=document.getElementById('gpanel');
  function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
  function clear(){edges.forEach(function(e){e.classList.remove('hl')});gnodes.forEach(function(n){n.classList.remove('sel','dim')});}
  function neighbours(id){var s={};s[id]=1;edges.forEach(function(e){if(e.dataset.s===id||e.dataset.t===id){e.classList.add('hl');s[e.dataset.s]=1;s[e.dataset.t]=1;}});return s;}
  function show(id){clear();var keep=neighbours(id);gnodes.forEach(function(n){if(!keep[n.dataset.id])n.classList.add('dim');if(n.dataset.id===id)n.classList.add('sel')});
    var n=data.nodes[id];if(!n)return;var h='<h3>'+esc(n.label)+'</h3><dl><dt>Type</dt><dd>'+esc(n.type)+'</dd>';
    if(n.own_risk)h+='<dt>Own risk</dt><dd>'+n.own_risk+' / 25</dd>';if(n.propagated_risk)h+='<dt>Propagated</dt><dd>'+n.propagated_risk+' / 25</dd>';
    Object.keys(n.props||{}).forEach(function(k){var v=n.props[k];if(v===null||v===''||(Array.isArray(v)&&!v.length))return;h+='<dt>'+esc(k)+'</dt><dd>'+esc(Array.isArray(v)?v.join(', '):typeof v==='object'?JSON.stringify(v):v)+'</dd>'});
    h+='</dl>';var fs=data.findings_by_node[id]||[];if(fs.length){h+='<div><b>Findings</b><ul style="margin:4px 0 0;padding-left:16px">'+fs.map(function(f){return '<li><a href="#d-'+f[0]+'" data-open="'+f[0]+'">'+f[0]+'</a> '+esc(f[1])+'</li>'}).join('')+'</ul></div>';}
    panel.innerHTML=h;}
  gnodes.forEach(function(n){n.addEventListener('click',function(){show(n.dataset.id)});n.addEventListener('keydown',function(e){if(e.key==='Enter')show(n.dataset.id)});});
  panel.addEventListener('click',function(e){var a=e.target.closest('[data-open]');if(!a)return;var d=document.getElementById('d-'+a.dataset.open);if(d){d.hidden=false;var r=document.querySelector('tr.frow[data-id="'+a.dataset.open+'"]');if(r)r.hidden=false;}});
  // ---- attack paths highlight
  document.querySelectorAll('.apath').forEach(function(b){b.addEventListener('click',function(){
    var on=b.getAttribute('aria-pressed')!=='true';document.querySelectorAll('.apath').forEach(function(x){x.setAttribute('aria-pressed','false')});clear();
    if(!on){panel.innerHTML='<p class="muted">Click a node or an attack path.</p>';return;}
    b.setAttribute('aria-pressed','true');var ids=JSON.parse(b.dataset.nodes);var set={};ids.forEach(function(i){set[i]=1});
    gnodes.forEach(function(n){if(!set[n.dataset.id])n.classList.add('dim');else n.classList.add('sel')});
    for(var i=0;i<ids.length-1;i++){edges.forEach(function(e){if(e.dataset.s===ids[i]&&e.dataset.t===ids[i+1])e.classList.add('hl')})}
    panel.innerHTML='<h3>'+esc(b.dataset.id)+' · APCR '+esc(b.dataset.apcr)+'</h3><ol style="margin:0;padding-left:18px">'+ids.map(function(i){var n=data.nodes[i];return '<li>'+esc(n?n.type+': '+n.label:i)+'</li>'}).join('')+'</ol>';
    document.getElementById('graph').scrollIntoView({behavior:'smooth',block:'start'});});});
})();
"""


NAV_CSS = """
.navlinks{display:flex;flex-wrap:wrap;gap:6px}
.navlinks a{font:600 12.5px var(--f-body);border:1px solid var(--line);background:var(--surface);color:var(--fg);
  border-radius:999px;padding:4px 12px;text-decoration:none}
.navlinks a:hover{border-color:var(--accent)}
"""

GRAPH_PAGE_CSS = NAV_CSS + """
.wrap.gwide{max-width:1680px;gap:20px}
.gpage{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:16px;align-items:start}
.gpage .gmain{display:grid;gap:10px;min-width:0}
.gpage .gside{position:sticky;top:8px;display:grid;gap:10px;max-height:calc(100vh - 16px);overflow:auto;padding-bottom:8px}
.gpage .gside .gpanel{position:static;max-height:none;box-shadow:none}
.gpage .gside .apath{grid-template-columns:auto minmax(0,1fr);padding:8px 10px}
.gpage .gside .apath .apcr{font-size:17px;min-width:40px}
.gpage .gside .hops{font-size:12px}
.gpage .tgraph{width:100%;height:auto;min-width:900px}
@media (max-width:1000px){.gpage{grid-template-columns:1fr}.gpage .gside{position:static;max-height:none}}
"""


def build_dashboard(analysis: dict, eujf: dict, history: list[dict], out_path, timings: dict | None = None,
                    phase1_report: str | None = "report.html", fragment: bool = False,
                    view: str = "full", nav: list[tuple[str, str]] | None = None) -> str:
    """view="full" is the whole dashboard; view="graph" is a page with only the threat graph and attack paths.
    nav adds links in the header, e.g. [("Home", "index.html")]."""
    s, plan = analysis["summary"], analysis["mitigation_plan"]
    findings, paths = analysis["findings"], analysis["attack_paths"]
    nodes = {n["id"]: n for n in analysis["graph"]["nodes"]}
    target = analysis.get("target") or "target"
    label = next((h.get("label") for h in history if h["run_id"] == analysis["run_id"]), None)
    timings = timings or {}

    # ---- pipeline strip
    def stage(n, name, sub, key):
        t = timings.get(key)
        return (f'<div class="stage done"><b>{n} · {name}</b><span>{sub}'
                f'{f" · {t:.0f} ms" if isinstance(t, (int, float)) else ""}</span></div>')

    pipe = ('<div class="pipe">' + stage(1, "Extractor", "4 sources", "phase1_ms") + stage(2, "API Normalizer", "EUJF + inventory", "phase2_ms")
            + stage(3, "Analysis &amp; risk", f"{s['rules_evaluated']} rules, graph", "phase3_ms") + stage(4, "Output", "this page", "phase4_ms") + "</div>")

    # ---- KPIs + severity bar
    total = max(1, s["findings"])
    colors = {"critical": "var(--crit)", "high": "var(--sev-high)", "medium": "var(--warn)", "low": "var(--info)"}
    bar = "".join(f'<i style="width:{100 * s["by_severity"][k] / total:.2f}%;background:{colors[k]}" title="{k}: {s["by_severity"][k]}"></i>'
                  for k in SEVS if s["by_severity"][k])
    kpis = f"""
    <div class="kpis">
      <div class="kpi"><b>{s['total_path_risk']:g}</b><span>attack-path risk (sum of APCR)</span></div>
      <div class="kpi"><b>{s['findings']}</b><span>findings from {s['rules_fired']} of {s['rules_evaluated']} rules</span></div>
      <div class="kpi"><b style="color:var(--crit)">{s['by_severity']['critical']}</b><span>critical findings</span></div>
      <div class="kpi"><b>{s['attack_paths']}</b><span>attack paths ({s['critical_paths']} high or critical)</span></div>
      <div class="kpi"><b>{s['endpoints']}</b><span>endpoints in {s['services']} services</span></div>
      <div class="kpi"><b style="color:var(--warn)">{s['shadow_endpoints']}</b><span>shadow endpoints</span></div>
    </div>
    <div style="display:grid;gap:6px"><div class="sevbar" role="img" aria-label="Findings by severity">{bar}</div>
    <div class="legend">{"".join(f'<span><i class="box" style="--c:{colors[k]}"></i>{k} {s["by_severity"][k]}</span>' for k in SEVS)}</div></div>"""

    insights = "".join(f"<li>{x}</li>" for x in _insights(analysis, eujf, history))

    # ---- findings table
    grp_short = {"Token security": "token", "API OWASP Top 10": "owasp", "Logging and tracing": "logging"}
    src_colors = [("openapi", "--src-spec", "OpenAPI"), ("runtime_traffic", "--src-traffic", "Traffic"),
                  ("infrastructure", "--src-infra", "K8s"), ("callchain", "--src-trace", "Traces")]

    def minisrc(srcs):
        return '<span class="sources-mini">' + "".join(
            f'<i style="--c:var({c})" class="{"" if k in srcs else "off"}" title="{n}{"" if k in srcs else " (not used)"}"></i>'
            for k, c, n in src_colors) + "</span>"

    frows = []
    for f in findings:
        refs = (_owasp_link(f["owasp"]) + " · " + " ".join(_cwe_link(c) for c in f["cwe"]) + " · ATT&amp;CK "
                + " ".join(_attack_link(t) for t in f["attack"]) + " · " + " ".join(_nist_link(n) for n in f["nist"]))
        risk_t = RISKS[f["risk"]][0]
        snip = f"<pre>{E(f['snippet'])}</pre>" if f["snippet"] else ""
        frows.append(
            f'<tr class="frow" tabindex="0" aria-expanded="false" data-id="{f["id"]}" data-sev="{f["severity"]}" data-grp="{grp_short[f["group"]]}">'
            f'<td class="mono">{f["id"]}</td><td>{_sev(f["severity"])}</td>'
            f'<td class="num"><span class="score">{f["score"]}</span> <span class="muted">{f["likelihood"]}×{f["impact"]}</span></td>'
            f'<td><b>{E(f["title"])}</b><br><span class="muted mono">{E(f["rule_id"])} · {E(f["owasp"].split(" ")[0])}</span></td>'
            f'<td class="path">{E(f["affected_api"])}<br><span class="muted">{"whole service" if f["target_kind"] == "service" else E(f["service"])}</span></td>'
            f'<td>{minisrc(f["sources"])}</td><td class="num">{f["attack_paths"] or "–"}</td></tr>'
            f'<tr class="fdetail" id="d-{f["id"]}" hidden><td colspan="7"><div class="fbody">'
            f'<div><h4>What was found</h4><p>{E(f["detail"])}</p><p class="muted" style="margin-top:6px">{E(f["description"])}</p></div>'
            f'<div><h4>Evidence ({f["confidence"]} confidence)</h4><ul>{"".join(f"<li>{E(x)}</li>" for x in f["evidence"])}</ul>'
            f'<p class="muted" style="margin-top:6px">Sources: {E(", ".join(f["sources"]))}</p></div>'
            f'<div><h4>Why score {f["score"]} ({f["severity"]})</h4><ul>{"".join(f"<li>{E(x)}</li>" for x in f["factors"])}</ul>'
            f'<p style="margin-top:6px">Leads to: <b>{E(risk_t)}</b>. Best attack path APCR {f["best_apcr"]:g}.</p></div>'
            f'<div><h4>Recommendation</h4><p><b>{E(f["recommendation"])}</b></p><ol style="margin-top:6px">'
            f'{"".join(f"<li>{E(m)}</li>" for m in f["mitigation"])}</ol>'
            f'{snip}</div>'
            f'<div style="grid-column:1/-1"><h4>Based on</h4><div class="refs">{refs}</div></div>'
            f'</div></td></tr>')
    filters = ('<div class="filters" role="group" aria-label="Severity">'
               + "".join(f'<button class="filter" type="button" data-k="sev" data-v="{v}" aria-pressed="{str(v == "all").lower()}">{v}'
                         f'{"" if v == "all" else " " + str(s["by_severity"][v])}</button>' for v in ["all"] + SEVS)
               + '</div><div class="filters" role="group" aria-label="Rule group">'
               + "".join(f'<button class="filter" type="button" data-k="grp" data-v="{k}" aria-pressed="{str(k == "all").lower()}">{n}</button>'
                         for k, n in [("all", "all groups"), ("token", "Token security"), ("owasp", "API OWASP Top 10"), ("logging", "Logging and tracing")])
               + "</div>")
    more = (f'<button class="filter" type="button" id="showall" aria-expanded="false">Show all {len(findings)} findings</button>'
            if len(findings) > 12 else "")
    ftable = ('<div class="scroll"><table class="findings"><thead><tr><th>ID</th><th>Severity</th><th class="num">Risk L×I</th>'
              '<th>Finding</th><th>Affected API</th><th>Sources</th><th class="num">Paths</th></tr></thead><tbody>'
              + "".join(frows) + "</tbody></table></div>" + more)

    # ---- attack paths
    def hops(p):
        out = []
        for i, nid in enumerate(p["nodes"]):
            n = nodes.get(nid, {"type": "?", "label": nid})
            lab = n["label"]
            out.append(f'<span class="hop t-{n["type"]}">{E(lab)}</span>')
        return '<span class="arrow">→</span>'.join(out)

    shown, seen_f = [], set()
    for p in paths:  # one path per finding in the list, best first
        if p["finding_id"] in seen_f:
            continue
        seen_f.add(p["finding_id"])
        shown.append(p)
        if len(shown) == 10:
            break
    path_html = "".join(
        f'<button class="apath" type="button" aria-pressed="false" data-id="{p["id"]}" data-apcr="{p["apcr"]:g}" '
        f'data-nodes="{E(json.dumps(p["nodes"]))}"><span class="apcr">{p["apcr"]:g}</span>'
        f'<span class="hops">{hops(p)}</span>'
        f'<span>{_sev(p["severity"])}</span><span class="muted" style="font-size:12.5px">{p["hops"]} hops · '
        f'{"internet" if p["entry"] == "actor:internet" else "in-cluster foothold"}</span></button>' for p in shown)

    # ---- graph data for the panel
    fby = defaultdict(list)
    for f in findings:
        fby[f["target"]].append([f["id"], f["title"]])
        fby[f"vuln:{f['id']}"].append([f["id"], f["detail"]])
    gdata = {"nodes": {n["id"]: {k: n.get(k) for k in ("type", "label", "props", "own_risk", "propagated_risk")} for n in nodes.values()},
             "findings_by_node": fby}
    legend = "".join(f'<span><i style="--c:var({c})"></i>{t}</span>' for t, c in [
        ("Actor", "--t-actor"), ("API", "--t-api"), ("Endpoint", "--t-endpoint"), ("Dependency", "--t-dep"),
        ("Vulnerability", "--t-vuln"), ("Risk", "--t-risk")])

    # ---- mitigation plan
    steps = "".join(
        f'<div class="step"><span class="n">{i}</span><div class="t"><b>{E(st["title"])}</b>'
        f'<small>{E(", ".join(st["finding_ids"]))} · rules {E(", ".join(sorted(set(st["rules"]))))}</small></div>'
        f'<div class="cum"><span>−{st["risk_removed"]:g} · total −{st["cumulative_reduction_pct"]:g}%</span>'
        f'<span class="bar"><i style="width:{st["cumulative_reduction_pct"]}%"></i></span></div></div>'
        for i, st in enumerate(plan["steps"], 1))

    # ---- inventory
    svc_risk = {n["label"]: n.get("propagated_risk", 0) for n in nodes.values() if n["type"] == "API"}
    fcount = defaultdict(int)
    for f in findings:
        fcount[f["target"]] += 1
    tone = {"documented": "ok", "shadow": "warn", "zombie": "warn", "dormant": "info"}
    auth_tone = {"enforced": "ok", "declared": "info", "not_enforced": "crit", "unknown": "info"}
    inv_rows = []
    for e in eujf["endpoints"]:
        srcs = {"spec": "openapi", "traffic": "runtime_traffic", "public_traffic": "runtime_traffic", "trace": "callchain"}
        used = {srcs[k] for k in e["sources"] if k in srcs}
        if e["gateway_route"] or e["service"] == eujf.get("gateway"):
            used.add("infrastructure")
        inv_rows.append([
            f'<span class="method">{E(e["method"])}</span>', f'<span class="mono">{E(e["path"])}</span>',
            E(e["service"]), f'<span class="mono">{E(", ".join(e["public_paths"]) or "internal only")}</span>',
            _chip(e["inventory_status"], tone[e["inventory_status"]]), _chip(e["auth_required"].replace("_", " "), auth_tone[e["auth_required"]]),
            E(", ".join(e["data_classes"]) or "–"), minisrc(used), str(fcount.get(e["id"], 0) or "–")])
    inv_table = ('<div class="scroll"><table class="inv"><thead><tr><th>Method</th><th>Path</th><th>Service</th><th>Public path</th>'
                 '<th>Inventory</th><th>Auth observed</th><th>Sensitive data</th><th>Sources</th><th class="num">Findings</th></tr></thead><tbody>'
                 + "".join("<tr>" + "".join(f'<td class="{"num" if i == 8 else "path" if i in (1, 3) else ""}">{c}</td>' for i, c in enumerate(r)) + "</tr>"
                           for r in inv_rows) + "</tbody></table></div>")
    dep = analysis["dependency"]
    svcs = {x["name"]: x for x in eujf["services"]}
    dep_rows = "".join(
        f'<tr><td><b>{E(r["service"])}</b></td><td>{_chip(svcs.get(r["service"], {}).get("exposure", {}).get("level", "?"), "crit" if svcs.get(r["service"], {}).get("exposure", {}).get("level") == "internet" else "info")}</td>'
        f'<td>{E(", ".join(r["called_by"]) or "–")}</td><td>{E(", ".join(r["calls"]) or "–")}</td>'
        f'<td>{E(", ".join(r["blast_radius"]) or "–")}</td><td class="num">{svc_risk.get(r["service"], 0):g}</td></tr>'
        for r in dep["services"])
    dep_table = ('<div class="scroll"><table><thead><tr><th>Service</th><th>Exposure</th><th>Called by</th><th>Calls</th>'
                 '<th>Affected if it fails (upstream)</th><th class="num">Propagated risk</th></tr></thead><tbody>' + dep_rows + "</tbody></table></div>")

    # ---- trend
    trend_rows = "".join(
        f'<tr><td class="mono">{E(h["run_id"])}{" (this run)" if h["run_id"] == analysis["run_id"] else ""}</td><td>{E(h.get("label") or "–")}</td>'
        f'<td class="num">{h["total_path_risk"]:g}</td><td class="num">{h["findings"]}</td>'
        + "".join(f'<td class="num">{h["by_severity"].get(k, 0)}</td>' for k in SEVS) + f'<td class="num">{h["attack_paths"]}</td></tr>'
        for h in history)
    trend_table = ('<div class="scroll"><table><thead><tr><th>Run</th><th>Scenario</th><th class="num">Path risk</th><th class="num">Findings</th>'
                   + "".join(f'<th class="num">{k}</th>' for k in SEVS) + '<th class="num">Paths</th></tr></thead><tbody>' + trend_rows + "</tbody></table></div>")

    # ---- rule catalog
    fired = defaultdict(int)
    for f in findings:
        fired[f["rule_id"]] += 1
    cat_rows = "".join(
        f'<tr><td class="mono">{E(r["id"])}</td><td><b>{E(r["title"])}</b><br><span class="muted">{E(r["group"])}</span></td>'
        f'<td>{_owasp_link(r["owasp"])}</td><td>{" ".join(_cwe_link(c) for c in r["cwe"])}</td>'
        f'<td>{" ".join(_attack_link(t) for t in r["attack"])}</td><td>{" ".join(_nist_link(n) for n in r["nist"])}</td>'
        f'<td class="num">{r["likelihood"]}×{r["impact"]}</td><td class="num">{fired.get(r["id"], 0) or "–"}</td></tr>'
        for r in catalog())
    cat_table = ('<div class="scroll"><table><thead><tr><th>Rule</th><th>What it checks</th><th>OWASP API 2023</th><th>CWE</th>'
                 '<th>MITRE ATT&amp;CK</th><th>NIST</th><th class="num">Base L×I</th><th class="num">Fired</th></tr></thead><tbody>'
                 + cat_rows + "</tbody></table></div>")

    tm = analysis["timing"]
    gjson = json.dumps(gdata).replace("</", "<\\/")
    navhtml = ('<nav class="navlinks" aria-label="Pages">'
               + "".join(f'<a href="{E(h)}">{E(t)}</a>' for t, h in nav) + "</nav>") if nav else ""
    if view == "graph":
        n_edges = sum(1 for e in analysis["graph"]["edges"] if e["rel"] != "runs_on")
        body = f"""
<title>{E(target)} threat graph</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=JetBrains+Mono:wght@400;600;700&family=Public+Sans:wght@400;600;700&display=swap">
<style>{CSS}{GRAPH_PAGE_CSS}</style>
<div class="wrap gwide">
  <header class="head">
    <div class="eyebrow">Threat graph · output of Phase 3</div>
    <h1>{E(target)}{f" ({E(label)})" if label else ""}: threat graph</h1>
    <div class="meta"><span>run {E(analysis['run_id'])}</span><span>graph store {E(analysis['store'])}</span>
    <span>{len(nodes)} nodes · {n_edges} edges</span><span>attack path query {tm['attack_path_query_ms']:g} ms</span></div>
    {navhtml}
  </header>
  {kpis}
  <section aria-labelledby="h-graph" id="graph" class="gpage">
    <div class="gmain">
      <h2 id="h-graph" class="sr-only" style="position:absolute;left:-9999px">Threat graph</h2>
      <div class="tlegend">{legend}</div>
      <p class="muted" style="margin:0">Columns follow the node types. The number on a node is its propagated risk (0 to 25).
      Click a node to see its details and neighbours, or pick an attack path on the right to trace it.</p>
      <div class="scroll">{_graph_svg(analysis)}</div>
    </div>
    <aside class="gside">
      <div class="gpanel" id="gpanel" aria-live="polite"><p class="muted">Click a node or an attack path.</p></div>
      <h3>Top attack paths (APCR)</h3>
      <div class="paths">{path_html or "<p class='muted'>No attack paths.</p>"}</div>
    </aside>
  </section>
</div>
<script type="application/json" id="gdata">{gjson}</script>
<script>{JS}</script>
"""
        page = body if fragment else (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>'
            + body + "</body></html>")
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(page, encoding="utf-8")
        return str(out_path)
    body = f"""
<title>{E(target)} Threat Graph</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=JetBrains+Mono:wght@400;600;700&family=Public+Sans:wght@400;600;700&display=swap">
<style>{CSS}{NAV_CSS}</style>
<div class="wrap">
  <header class="head">
    <div class="eyebrow">Automatic API Security Design Review · Phases 1–4</div>
    <h1>{E(target)}: threat graph with propagated risk</h1>
    <p class="muted">Every finding below comes from the four discovery sources, merged into one API inventory and checked by
    {s['rules_evaluated']} deterministic rules. Each one names the standard it is based on and how to fix it.</p>
    <div class="meta"><span>run {E(analysis['run_id'])}</span>{f"<span>scenario {E(label)}</span>" if label else ""}
    <span>graph store {E(analysis['store'])}</span><span>rules {tm['rule_engine_ms']:g} ms · attack paths {tm['attack_path_query_ms']:g} ms</span></div>
    {navhtml}
    {pipe}
  </header>

  <section aria-labelledby="h-risk">
    <h2 id="h-risk">Risk summary</h2>
    {kpis}
    <h3>Insight</h3>
    <ul class="insights">{insights}</ul>
  </section>

  <section aria-labelledby="h-top">
    <h2 id="h-top">Top vulnerabilities</h2>
    <p class="muted">Risk = likelihood × impact (1–25). Click a row to see the evidence, how the score was built,
    the standards behind the rule, and the fix.</p>
    {filters}
    {ftable}
  </section>

  <section aria-labelledby="h-paths">
    <h2 id="h-paths">Attack paths</h2>
    <p class="muted">Found by a recursive query over the threat graph in the graph store. APCR (attack path contextual risk)
    = L × I × entry factor (internet 1.0, in-cluster 0.5) × 0.95 per chained call. Click a path to trace it on the graph.</p>
    <div class="paths">{path_html or "<p class='muted'>No attack paths.</p>"}</div>
  </section>

  <section aria-labelledby="h-graph" id="graph">
    <h2 id="h-graph">Threat graph</h2>
    <p class="muted">Columns follow the node types. The number on a node is its propagated risk: its own worst finding,
    or 0.85 × the worst risk it leads to, whichever is higher. Click any node.</p>
    <div class="tlegend">{legend}</div>
    <aside class="gpanel" id="gpanel" aria-live="polite"><p class="muted">Click a node or an attack path.</p></aside>
    <div class="scroll">{_graph_svg(analysis)}</div>
  </section>

  <section aria-labelledby="h-plan">
    <h2 id="h-plan">Recommended fixes, in order</h2>
    <p class="muted">Findings grouped into remediation actions (one code change often closes several findings), ordered by how
    much attack-path risk each removes. {f"<b>{plan['fixes_for_70pct']}</b> actions remove 70% of the risk." if plan['fixes_for_70pct'] else ""}</p>
    <div class="plan">{steps}</div>
  </section>

  <section aria-labelledby="h-api">
    <h2 id="h-api">API overview</h2>
    {inv_table}
    <h3>Service dependencies</h3>
    {dep_table}
  </section>

  <section aria-labelledby="h-trend">
    <h2 id="h-trend">Trend &amp; insight</h2>
    <p class="muted">Attack-path risk for every run of {E(target)} stored in the graph store. Run the demo again with
    <code>--scenario hardened</code> to see the effect of the fixes.</p>
    {_trend_svg(history, analysis['run_id'])}
    {trend_table}
  </section>

  <section aria-labelledby="h-rules">
    <h2 id="h-rules">Rule catalog</h2>
    <p class="muted">Where every rule comes from. Rules live in <code>atg/rules.py</code>; adding one is one decorated function.</p>
    {cat_table}
  </section>

  <section aria-labelledby="h-files">
    <h2 id="h-files">Files behind this page</h2>
    <p class="muted">{f'<a href="{E(phase1_report)}">Phase 1 extractor report</a> · ' if phase1_report else ''}<code>output/raw/*.json</code> (Phase 1)
    · <code>output/eujf.json</code> (Phase 2) · <code>output/analysis.json</code> (Phase 3) · graph tables <code>atg_*</code> in the graph store.</p>
  </section>
</div>
<script type="application/json" id="gdata">{gjson}</script>
<script>{JS}</script>
"""
    page = body if fragment else (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>'
        + body + "</body></html>")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")
    return str(out_path)
