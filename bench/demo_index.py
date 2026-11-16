"""
Write demo/index.html: one card per open-source system, linking the pages DEMO-ALL-Windows.bat /
demo-all.sh saves in demo/<id>/, with the system's GitHub link, the benchmark numbers and the finding
to point at during a demo.

    python bench/demo_index.py
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
from fetch import SYSTEMS  # noqa: E402

E = html.escape
REPO = "https://github.com/hiransangvantam-code/api-threat-graph/blob/main/"
POINT_AT = {
    "online-boutique": "PaymentService.Charge takes a full card number from any pod in the cluster: no mTLS, no token (A5).",
    "bank-of-anthos": "The front end sends the user name and password in the URL of the login call to userservice (A7).",
    "robot-shop": "GET /api/user/users lists every user, password field included, to anyone (A1, A9).",
    "acme-air": "/customer/internal/updateCustomerTotalMiles is reachable through the Ingress by anyone (A3).",
    "petclinic": "No login anywhere: GET /owners returns every owner's address and phone number (A1, A9).",
    "piggymetrics": "The OAuth2 password grant has no rate limit or lockout (A6); the Zuul gateway forwards without auth.",
    "lakeside-mutual": "Any logged-in customer can read any other customer's record: no owner check (A2, BOLA).",
    "ftgo": "Anyone can cancel or revise any order: POST /orders/{id}/cancel needs no login (A1).",
    "hotel-reservation": "User name and password travel in the query string of every reservation (A7).",
    "bookinfo": "9 of 13 operations are missing from its swagger.yaml (shadow APIs); its services call each other with no credential (A5).",
}


def main() -> int:
    scores = {s["system"]: s for s in json.loads((ROOT / "results/opensource/atg-v1.5/scores.json").read_text())}
    cards = []
    for sid in SYSTEMS:
        y = yaml.safe_load((ROOT / "opensource" / sid / "system.yaml").read_text(encoding="utf-8"))
        up = y["upstream"]
        if up.get("repos"):
            gh_url = "https://github.com/blueperf"
            gh_text = "github.com/blueperf (5 repositories)"
        else:
            sub = f"/tree/{up['commit']}/{up['sparse']}" if up.get("sparse") else f"/tree/{up['commit']}"
            gh_url = up["repo"] + sub
            gh_text = up["repo"].replace("https://", "") + (f"/{up['sparse']}" if up.get("sparse") else "")
        s = scores.get(sid, {})
        found = f"{s.get('found', 0)}/{s.get('labels', 0)}" if s else "–"
        pages = [("Home", "index.html"), ("Threat graph", "threat-graph.html"),
                 ("What to fix", f"hardening-1-{sid}.html"), ("Dashboard", f"dashboard-1-{sid}.html")]
        links = " ".join(f'<a class="btn" href="{sid}/{p}">{t}</a>' for t, p in pages)
        cards.append(f"""<article>
<header><h2>{E(y['name'])}</h2><span class="field">{E(y['field'])}</span></header>
<p class="meta">{E(y.get('by', ''))} · {E(', '.join(y['languages']))} · {len(y['services'])} services</p>
<p class="links">{links}</p>
<p class="point"><b>Point at:</b> {E(POINT_AT.get(sid, ''))}</p>
<p class="meta">Benchmark (ATG v1.5): {found} labelled weaknesses found ·
<a href="{E(gh_url)}">{E(gh_text)}</a> · <a href="{sid}/scan.log">scan log</a></p>
</article>""")
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ATG: ten open-source systems</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f5f6f8;color:#1c2430}}
main{{max-width:1100px;margin:0 auto;padding:32px 24px 48px}}
h1{{font-size:28px;margin:0 0 6px}} .lead{{color:#4b5563;max-width:820px;margin:0 0 20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}}
article{{background:#fff;border:1px solid #dde1e7;border-radius:10px;padding:14px 16px}}
article header{{display:flex;justify-content:space-between;align-items:baseline;gap:8px}}
h2{{font-size:17px;margin:0}} .field{{font-size:12px;color:#9a3412;background:#fff1e8;border-radius:10px;padding:1px 8px;white-space:nowrap}}
.meta{{font-size:13px;color:#6b7280;margin:6px 0}} .point{{font-size:14px;margin:8px 0}}
.btn{{display:inline-block;font-size:13px;border:1px solid #cfd5dd;border-radius:14px;padding:2px 10px;margin:2px 4px 2px 0;color:#1c2430;text-decoration:none}}
.btn:hover{{background:#eef1f5}} a{{color:#1d4ed8}}
.note{{font-size:13px;color:#6b7280;margin-top:24px;max-width:820px}}
table{{border-collapse:collapse;font-size:14px;margin:6px 0 22px;background:#fff}} td,th{{border:1px solid #dde1e7;padding:5px 10px;text-align:right}} th:first-child,td:first-child{{text-align:left}}
</style></head><body><main>
<h1>ATG on ten open-source systems</h1>
<p class="lead">Ten published microservice systems from Google, IBM, Spring, Cornell, Istio and others, each reviewed
by ATG: its own deployment files and API documents, plus the traffic and traces of its services. Each card opens
that system's saved review.</p>
<table><tr><th>On all ten</th><th>ATG v1.5</th><th>Polaris (best Kubernetes scanner)</th><th>ATG + Checkov</th></tr>
<tr><td>Systems it can run on</td><td>10/10</td><td>7/10</td><td>10/10</td></tr>
<tr><td>Labelled weaknesses found (of 716)</td><td>466 (65%)</td><td>331 (46%)</td><td>613 (86%)</td></tr>
<tr><td>API behaviour / inventory labels</td><td>52/82 · 88/88</td><td>0 · 0</td><td>52/82 · 88/88</td></tr></table>
<div class="grid">
{chr(10).join(cards)}
</div>
<p class="note">The pages come from <code>DEMO-ALL-Windows.bat</code> (or <code>sh demo-all.sh</code>); a card whose
buttons do not open has not been run yet. The running services are stand-ins built from each system's code; the
deployment files and API documents ATG reads are the systems' own. Full comparison:
<a href="{REPO}results/opensource/comparison.md">comparison.md</a> ·
<a href="{REPO}docs/BENCHMARK_OSS.md">BENCHMARK_OSS.md</a> ·
<a href="{REPO}docs/TOOLS_COMPARISON.md">TOOLS_COMPARISON.md</a> (IBM, NVIDIA and other commercial tools).</p>
</main></body></html>
"""
    out = ROOT / "demo" / "index.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(page, encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
