"""Tables for the ATG vs OWASP ZAP comparison: results/zap/zap.json -> results/zap/tables.md"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "results" / "zap"

# Our reading of every alert type ZAP raised on ShopLite (checked against the responses).
JUDGEMENT = {
    "X-Content-Type-Options Header Missing": ("real, minor hardening issue", "no: ATG has no response-header rule"),
    "Information Disclosure - Sensitive Information in URL": (
        "not a real issue here: user_id is not secret. The actual weakness on this endpoint is BOLA through that "
        "parameter, which ZAP does not report", "no, and ATG misses that BOLA too (one of the 3 uncovered weaknesses)"),
    "Authentication Request Identified": ("not a weakness: ZAP noting a login endpoint", "–"),
    "User Agent Fuzzer": ("not a weakness: ZAP records how responses vary by user agent", "–"),
}


def _split(planted: set, uncovered: list) -> tuple[list, list]:
    """Weaknesses on one endpoint vs service/configuration-level ones (manifests, gateway config)."""
    endpoint = [p for p in planted if isinstance(p[1], tuple)] + [u for u in uncovered if isinstance(u[1], tuple)]
    service = [p for p in planted if not isinstance(p[1], tuple)] + [u for u in uncovered if not isinstance(u[1], tuple)]
    return endpoint, service


def report() -> None:
    f = OUT / "zap.json"
    if not f.exists():
        print("no results/zap/zap.json yet")
        return
    from bench.evaluate_threat import SHOPLITE_PLANTED, SHOPLITE_UNCOVERED

    d = json.loads(f.read_text(encoding="utf-8"))
    s, atg = d["score"], d.get("atg", {})
    endpoint, service = _split(SHOPLITE_PLANTED, SHOPLITE_UNCOVERED)

    def as_set(found_items):
        return {(r, tuple(t) if isinstance(t, list) else t) for r, t in found_items}
    atg_found = as_set(s["atg"].get("found_items", []))
    shadow_total = 4

    rows = []
    t = atg.get("timings", {})
    rows.append(["ATG (this tool)", "passive", f"{atg.get('requests_to_target', '–')} (OpenAPI probes)",
                 f"{atg.get('pipeline_ms', 0) / 1000:.2f} s for Phases 1-4; {atg.get('scan_wall_s', '–')} s per scan with the wait for the buffers to go quiet",
                 f"{s['atg']['endpoints']}/12", f"{shadow_total}/{shadow_total}",
                 f"{len([p for p in atg_found if isinstance(p[1], tuple)])}/{len(endpoint)}",
                 f"{len([p for p in atg_found if not isinstance(p[1], tuple)])}/{len(service)}",
                 f"{s['atg']['found']}/{s['planted_total']}", "0"])
    for mode, name in (("gateway", "ZAP, through the gateway"), ("internal", "ZAP, inside the network")):
        z = s.get(mode)
        if not z:
            continue
        real = sum(1 for a in z["alert_types"] if JUDGEMENT.get(a["alert"], ("",))[0].startswith("real"))
        found = as_set(z["found_items"])
        rows.append([name, "active (DAST)", f"{z['messages']:,}", f"{z['total_s']:.1f} s",
                     f"{z['endpoints_touched']}/12", f"0/{shadow_total}",
                     f"{len([p for p in found if isinstance(p[1], tuple)])}/{len(endpoint)}",
                     f"{len([p for p in found if not isinstance(p[1], tuple)])}/{len(service)}",
                     f"{z['found']}/{s['planted_total']}", str(real)])
    lines = ["## Table 23. ATG vs OWASP ZAP on the same ShopLite build (vulnerable)", "",
             f"ZAP {d['zap_version']}, default active scan policy, the OpenAPI documents ATG used (converted to 3.0.3), "
             "no login. Planted weaknesses as in Table 16: 40, of which 3 no ATG rule covers. 'Other real issues' are "
             "valid findings outside the planted list.", "",
             "| Tool | Kind | Requests sent to the target | Time | Endpoints reached | Shadow endpoints found | "
             "Planted, endpoint level | Planted, service/config level | Planted, all | Other real issues |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    lines += ["", "## Table 24. Every alert type ZAP raised, and what it means", "",
              "| Alert | Risk | CWE | Instances (gateway / internal) | Endpoints | Our reading | Does ATG report it? |",
              "|---|---|---|---|---|---|---|"]
    types = {}
    for mode in ("gateway", "internal"):
        for a in s.get(mode, {}).get("alert_types", []):
            t = types.setdefault(a["alert"], {"risk": a["risk"], "cwe": a["cwe"], "n": {}, "eps": set()})
            t["n"][mode] = t["n"].get(mode, 0) + a["instances"]
            t["eps"] |= set(a["endpoints"])
    order = ["High", "Medium", "Low", "Informational"]
    for name, t in sorted(types.items(), key=lambda kv: (order.index(kv[1]["risk"]), kv[0])):
        j = JUDGEMENT.get(name, ("not reviewed", "–"))
        eps = ", ".join(sorted(t["eps"])) or "–"
        lines.append(f"| {name} | {t['risk']} | {t['cwe'] if t['cwe'] not in ('-1', '0') else '–'} | "
                     f"{t['n'].get('gateway', 0)} / {t['n'].get('internal', 0)} | {eps} | {j[0]} | {j[1]} |")
    side = OUT / "zap-openapi31-as-served.json"
    if side.exists():
        sd = json.loads(side.read_text(encoding="utf-8"))["score"]
        lines += ["", f"With the services' OpenAPI 3.1 documents as served, ZAP reached {sd['gateway']['endpoints_touched']}/12 "
                  f"endpoints through the gateway and {sd['internal']['endpoints_touched']}/12 inside, because it left every "
                  "path and query parameter empty. Planted weaknesses found: "
                  f"{sd['gateway']['found']} and {sd['internal']['found']}."]
    (OUT / "tables.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    report()
