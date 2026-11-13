# Exporting the threat graph: which format, and why

Every scan writes its threat graph to `output/site/exports/<scan>/` in four files. They are linked from the home page (section "Export the threat graph") and from the top of each threat graph page. From a stored run they can be made again with:

```sh
python -m atg.export <folder with analysis.json and eujf.json> <output folder>
```

| File | Format | What is in it | Open it with |
|---|---|---|---|
| `threat-graph.graphml` | GraphML 1.0 (XML) | The graph: every node with its type, label, own and propagated risk and its properties; every edge with its relation (eq. 3) and properties. Endpoint nodes also carry their EUJF record: `api_id`, `http_method`, `endpoint`, `auth_scheme`, `confidence` and the four evidence flags. | Gephi, yEd, Cytoscape, Neo4j (`apoc.import.graphml` with `readLabels: true`), NetworkX (`nx.read_graphml`), igraph |
| `threat-graph.json` | node-link JSON (`atg.threat-graph/v1`) | The same nodes and edges (`nodes`, `links`), plus the findings, the ranked attack paths with their APCR and the fix plan. | Python (`nx.node_link_graph(data, edges="links")`), JavaScript and D3, or ATG itself to rebuild the pages |
| `findings.sarif` | SARIF 2.1.0 (OASIS standard) | The findings only: one result per finding with the rule (OWASP, CWE, Table I ID, likelihood, impact), the affected API, the evidence, the best APCR and a fingerprint that stays the same across scans. | SARIF Viewer for VS Code, DefectDojo and other vulnerability trackers, CI pipelines |
| `threat-graph.svg` | SVG 1.1 | The drawing from the dashboard, as a vector image with its own styles. | Any browser, Word, PowerPoint, Inkscape (to PDF for LaTeX) |

## Which one to use

**GraphML is the main format for the graph.** It is an open standard that most graph tools read, it keeps directed edges and typed attributes (numbers stay numbers), and it needs no special software. A picture (PNG, PDF) cannot be analysed further, and a database dump ties the reader to PostgreSQL.

**SARIF for the findings.** When the company wants the findings in its own tracker or pipeline, SARIF is the format security tools share. The `partialFingerprints` value is a hash of rule and target, so the same weakness found again in a later scan can be recognised as the same issue.

**JSON when someone writes code against the result**, or to keep a scan and rebuild its pages later. It is also the only file that has the attack paths and the fix plan.

**SVG for documents.** It stays sharp at any size, which matters for a graph with 70 nodes in a two-column paper.

Formats we did not pick:

- STIX 2.1 is made for sharing threat intelligence between organisations (indicators, campaigns). The threat graph describes one company's own system and is not meant to be shared outside it, and STIX has no natural object for an API endpoint or a gateway route.
- GEXF (Gephi's own format) and DOT (Graphviz) would add little. Gephi reads GraphML, and the layout comes from the SVG already.
- CSV per node type and edge type would suit a Neo4j bulk import, but GraphML imports into Neo4j directly.

## How the files were checked

- GraphML and JSON load into NetworkX 3.x with the same node and edge counts as the graph store (69 nodes, 132 edges for the ShopLite vulnerable build).
- `findings.sarif` validates against the official SARIF 2.1.0 JSON schema (`sarif-2.1.0.json`, from Microsoft's SARIF multitool). A deliberately broken copy fails the same check.
- The SVG renders on its own in Chromium, with the same colours as the dashboard.

## What is not in the exports

No traffic, no spans, no Phase 1 files, no header values or tokens. The exports hold the graph and the findings and nothing else, which is why they are the only review data kept after STOP (see `docs/DATA_HANDLING.md`). They still describe the company's weaknesses, so treat them as confidential.
