"""
Export the threat graph of one scan to files other tools can open.

    threat-graph.graphml   the graph itself (GraphML, an open XML standard). Opens in Gephi, yEd,
                           Cytoscape, NetworkX and Neo4j (apoc.import.graphml). Every node keeps
                           its type, risk scores and properties; Endpoint nodes also carry their
                           EUJF record (api_id, method, endpoint, auth, evidence, confidence).
    threat-graph.json      the same graph as node-link JSON (the format of NetworkX and D3), plus
                           the findings, ranked attack paths and fix plan. For scripts and for
                           loading a scan back later.
    findings.sarif         the findings in SARIF 2.1.0, the OASIS standard for results of security
                           tools, so they can go into a vulnerability tracker or a CI pipeline.
    threat-graph.svg       the drawing from the dashboard as a vector image, for reports and the paper.

    python -m atg.export output/runs/<run_id> exports/        # from a stored run

The exports are what is left of a review once its working data has been deleted, so they
hold the graph and the findings and nothing else: no traffic, no traces, no Phase 1 files.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from .dashboard import _graph_svg
from .rules import catalog

TOOL_NAME = "API Threat Graph"
TOOL_VERSION = "1.3.0"
TOOL_URI = "https://github.com/hiransangvantam-code/api-threat-graph"
FILES = {
    "graphml": "threat-graph.graphml",
    "json": "threat-graph.json",
    "sarif": "findings.sarif",
    "svg": "threat-graph.svg",
}


# ---------------------------------------------------------------- one flat record per node and edge
def _eujf_by_id(eujf: dict | None) -> dict[str, dict]:
    return {e["id"]: e for e in (eujf or {}).get("endpoints", []) if "id" in e}


def _eujf_fields(rec: dict) -> dict:
    ev = rec.get("evidence", {})
    return {"api_id": rec.get("api_id"), "http_method": rec.get("method"), "endpoint": rec.get("endpoint"),
            "auth_scheme": rec.get("auth"), "confidence": ev.get("confidence"),
            "evidence_traffic": ev.get("traffic_observed"), "evidence_openapi": ev.get("openapi_declared"),
            "evidence_gateway": ev.get("gateway_routed"), "evidence_trace": ev.get("trace_observed")}


def node_records(analysis: dict, eujf: dict | None = None) -> list[dict]:
    recs, by_id = [], _eujf_by_id(eujf)
    for n in analysis["graph"]["nodes"]:
        r = {"id": n["id"], "type": n["type"], "label": n["label"],
             "own_risk": float(n.get("own_risk", 0) or 0), "propagated_risk": float(n.get("propagated_risk", 0) or 0)}
        for k, v in (n.get("props") or {}).items():
            r.setdefault(k, v)
        if n["type"] == "Endpoint" and n["id"] in by_id:
            r.update({k: v for k, v in _eujf_fields(by_id[n["id"]]).items() if v is not None})
        recs.append(r)
    return recs


def edge_records(analysis: dict) -> list[dict]:
    out = []
    for i, e in enumerate(analysis["graph"]["edges"]):
        r = {"id": f"e{i}", "source": e["src"], "target": e["dst"], "rel": e["rel"]}
        for k, v in (e.get("props") or {}).items():
            r.setdefault(k, v)
        out.append(r)
    return out


# ---------------------------------------------------------------- GraphML
def _gtype(values: list) -> str:
    vals = [v for v in values if v is not None]
    if vals and all(isinstance(v, bool) for v in vals):
        return "boolean"
    if vals and all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return "long"
    if vals and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return "double"
    return "string"


def _gval(v, typ: str) -> str:
    if typ == "boolean":
        return "true" if v else "false"
    if typ in ("long", "double"):
        return repr(v) if isinstance(v, float) else str(v)
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return str(v)


def to_graphml(analysis: dict, eujf: dict | None = None) -> str:
    nodes, edges = node_records(analysis, eujf), edge_records(analysis)
    for n in nodes:  # Neo4j's apoc.import.graphml reads node labels from a "labels" attribute
        n["labels"] = ":" + n["type"]
    keys = []  # (for, name, type, id)

    def declare(kind, recs, skip):
        names = []
        for r in recs:
            for k in r:
                if k not in skip and k not in names:
                    names.append(k)
        out = {}
        for k in names:
            typ = _gtype([r.get(k) for r in recs])
            kid = f"{kind[0]}_{k}"
            keys.append((kind, k, typ, kid))
            out[k] = (kid, typ)
        return out

    nkeys = declare("node", nodes, {"id"})
    ekeys = declare("edge", edges, {"id", "source", "target"})
    s = analysis.get("summary", {})
    gdata = {"target": analysis.get("target", ""), "run_id": analysis.get("run_id", ""),
             "generated_at": (eujf or {}).get("generated_at", ""), "findings": s.get("findings", 0),
             "attack_paths": s.get("attack_paths", 0), "total_path_risk": float(s.get("total_path_risk", 0)),
             "producer": f"{TOOL_NAME} {TOOL_VERSION}"}
    gkeys = {k: (f"g_{k}", _gtype([v])) for k, v in gdata.items()}

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns" '
             'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
             'xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns '
             'http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">']
    for k, (kid, typ) in gkeys.items():
        lines.append(f'  <key id="{kid}" for="graph" attr.name={quoteattr(k)} attr.type="{typ}"/>')
    for kind, name, typ, kid in keys:
        lines.append(f'  <key id="{kid}" for="{kind}" attr.name={quoteattr(name)} attr.type="{typ}"/>')
    lines.append('  <graph id="threat-graph" edgedefault="directed">')
    for k, (kid, typ) in gkeys.items():
        lines.append(f'    <data key="{kid}">{escape(_gval(gdata[k], typ))}</data>')
    for n in nodes:
        lines.append(f"    <node id={quoteattr(n['id'])}>")
        for k, v in n.items():
            if k in nkeys and v is not None:
                kid, typ = nkeys[k]
                lines.append(f'      <data key="{kid}">{escape(_gval(v, typ))}</data>')
        lines.append("    </node>")
    for e in edges:
        lines.append(f"    <edge id={quoteattr(e['id'])} source={quoteattr(e['source'])} target={quoteattr(e['target'])}>")
        for k, v in e.items():
            if k in ekeys and v is not None:
                kid, typ = ekeys[k]
                lines.append(f'      <data key="{kid}">{escape(_gval(v, typ))}</data>')
        lines.append("    </edge>")
    lines += ["  </graph>", "</graphml>", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- node-link JSON
def to_json(analysis: dict, eujf: dict | None = None) -> dict:
    return {
        "schema": "atg.threat-graph/v1",
        "directed": True,
        "multigraph": True,
        "graph": {"target": analysis.get("target"), "run_id": analysis.get("run_id"),
                  "generated_at": (eujf or {}).get("generated_at"), "producer": f"{TOOL_NAME} {TOOL_VERSION}",
                  "summary": analysis.get("summary", {})},
        "nodes": node_records(analysis, eujf),
        "links": edge_records(analysis),
        "findings": analysis.get("findings", []),
        "attack_paths": analysis.get("attack_paths", []),
        "mitigation_plan": analysis.get("mitigation_plan", {}),
    }


# ---------------------------------------------------------------- SARIF 2.1.0
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _fingerprint(f: dict) -> str:
    """Same rule on the same API in a later scan -> same fingerprint, so a tracker can follow it."""
    return hashlib.sha256(f"{f['rule_id']}|{f['target']}".encode()).hexdigest()[:32]


def to_sarif(analysis: dict, eujf: dict | None = None) -> dict:
    rules = catalog()
    index = {r["id"]: i for i, r in enumerate(rules)}
    sarif_rules = []
    for r in rules:
        tags = ["security", r["group"]] + [t for t in (r["owasp"], r["table_i"]) if t] + list(r["cwe"])
        sarif_rules.append({
            "id": r["id"],
            "name": "".join(w.capitalize() for w in r["title"].replace("-", " ").split() if w.isalnum()) or r["id"],
            "shortDescription": {"text": r["title"]},
            "fullDescription": {"text": r["description"]},
            "help": {"text": " ".join(r["mitigation"]) or r["description"]},
            "defaultConfiguration": {"level": LEVEL.get(_sev(r["likelihood"] * r["impact"]), "warning")},
            "properties": {"tags": tags, "security-severity": f"{r['likelihood'] * r['impact'] / 2.5:.1f}",
                           "likelihood": r["likelihood"], "impact": r["impact"], "nist": r["nist"],
                           "attack": r["attack"]},
        })
    results = []
    for f in analysis.get("findings", []):
        res = {
            "ruleId": f["rule_id"],
            "level": LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']}: {f['affected_api']}. {f['detail']}"},
            "locations": [{"logicalLocations": [{
                "name": f["affected_api"],
                "fullyQualifiedName": f"{analysis.get('target', '')}/{f['service']}/{f['affected_api']}",
                "kind": "resource"}]}],
            "partialFingerprints": {"atgFinding/v1": _fingerprint(f)},
            "properties": {
                "finding_id": f["id"], "severity": f["severity"], "score": f["score"],
                "likelihood": f["likelihood"], "impact": f["impact"], "confidence": f.get("confidence"),
                "best_apcr": f.get("best_apcr", 0), "attack_paths": f.get("attack_paths", 0),
                "risk": f["risk"], "owasp": f["owasp"], "cwe": f["cwe"], "table_i": f.get("table_i", ""),
                "evidence": f["evidence"], "sources": f["sources"], "recommendation": f["recommendation"],
                "graph_node": f"vuln:{f['id']}", "target_node": f["target"],
            },
        }
        if f["rule_id"] in index:
            res["ruleIndex"] = index[f["rule_id"]]
        results.append(res)
    s = analysis.get("summary", {})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION, "informationUri": TOOL_URI,
                                "rules": sarif_rules}},
            "automationDetails": {"id": f"atg/{analysis.get('target', 'target')}/{analysis.get('run_id', '')}"},
            "results": results,
            "properties": {"target": analysis.get("target"), "run_id": analysis.get("run_id"),
                           "attack_paths": s.get("attack_paths", 0), "total_path_risk": s.get("total_path_risk", 0)},
        }],
    }


def _sev(score: float) -> str:
    return "critical" if score >= 20 else "high" if score >= 12 else "medium" if score >= 6 else "low"


# ---------------------------------------------------------------- SVG
SVG_STYLE = """
.tgraph{font-family:"Public Sans","Segoe UI",Arial,sans-serif}
.gcol{font:600 11px Consolas,Menlo,monospace;letter-spacing:.08em;fill:#5a6675}
.ge{fill:none;stroke:#d9dfe6;stroke-width:1.1;opacity:.9}
.ge.r-HAS_FINDING{stroke:#c2410c;opacity:.35}.ge.r-LEADS_TO{stroke:#be123c;opacity:.3}
.ge.r-CALLS{stroke:#7b45b5;stroke-dasharray:3 3}.ge.r-REACHES{stroke:#b8262d;opacity:.5}
.gn rect{fill:#eef1f4;stroke:#d9dfe6}.gn text{font-size:11.5px;fill:#17212b}
.gn .gscore{font:700 10.5px Consolas,Menlo,monospace}.gn circle{stroke:none}
.t-Actor circle{fill:#5a6675}.t-API circle{fill:#2563eb}.t-Endpoint circle{fill:#2c7a4b}
.t-Dependency circle{fill:#b7791f}.t-Vulnerability circle{fill:#c2410c}.t-Risk circle{fill:#be123c}
.risk-critical rect{stroke:#b8262d;stroke-width:1.6}.risk-critical .gscore{fill:#b8262d}
.risk-high rect{stroke:#c2410c;stroke-width:1.4}.risk-high .gscore{fill:#c2410c}
.risk-medium .gscore{fill:#a85d00}.risk-low .gscore{fill:#5a6675}
"""


def to_svg(analysis: dict) -> str:
    svg = _graph_svg(analysis)
    head, _, rest = svg.partition(">")
    head = head.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n{head}><style>{SVG_STYLE}</style>'
            f'<rect width="100%" height="100%" fill="#ffffff"/>{rest}\n')


# ---------------------------------------------------------------- all four
def export_all(analysis: dict, eujf: dict | None, out_dir) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {k: out / v for k, v in FILES.items()}
    paths["graphml"].write_text(to_graphml(analysis, eujf), encoding="utf-8")
    paths["json"].write_text(json.dumps(to_json(analysis, eujf), indent=1, ensure_ascii=False, default=list),
                             encoding="utf-8")
    paths["sarif"].write_text(json.dumps(to_sarif(analysis, eujf), indent=1, ensure_ascii=False, default=list),
                              encoding="utf-8")
    paths["svg"].write_text(to_svg(analysis), encoding="utf-8")
    if eujf is not None:   # the risk and hardening report, for people (atg/hardening.py)
        from atg.hardening import build_hardening
        paths["hardening"] = out / "hardening.md"
        paths["hardening"].write_text(build_hardening(analysis, eujf, analysis.get("timing"))[1], encoding="utf-8")
    return paths


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print("usage: python -m atg.export <run folder with analysis.json and eujf.json> <output folder>")
        return 2
    run = Path(argv[0])
    analysis = json.loads((run / "analysis.json").read_text(encoding="utf-8"))
    eujf_path = run / "eujf.json"
    eujf = json.loads(eujf_path.read_text(encoding="utf-8")) if eujf_path.exists() else None
    for kind, p in export_all(analysis, eujf, argv[1]).items():
        print(f"{kind:8s} {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
