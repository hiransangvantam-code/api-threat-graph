"""
Turn a system's own Kubernetes manifests into a Docker Compose file, so the real images can run
on a laptop without a cluster. Used for the systems that ship no compose file (Online Boutique,
Bookinfo). The output is written next to this script and committed, so it can be reviewed.

    python opensource/real/k8s2compose.py online-boutique
    python opensource/real/k8s2compose.py bookinfo

Each Deployment becomes one compose service with the same image, command, arguments and
literal environment values. Its network name is the Kubernetes Service that selects it (Bookinfo's
three reviews versions all answer as "reviews", the way the Service balances them). Values the
manifests take from fieldRef or resourceFieldRef are left out. A Service whose port differs from the
container port is rewritten in the callers' settings, since compose cannot remap a port inside
the network.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
OSS = HERE.parent

SOURCES = {
    "online-boutique": ["release/kubernetes-manifests.yaml"],
    "bookinfo": ["samples/bookinfo/platform/kube/bookinfo.yaml"],
}
# what each system needs on top of its manifests to run here
EXTRA_ENV = {
    # traces go to the ATG Collector (OTLP/gRPC); the profiler and Google Cloud stats stay off
    "online-boutique": {"ENABLE_TRACING": "1", "COLLECTOR_SERVICE_ADDR": "atg-collector:4317",
                        "OTEL_SERVICE_NAME": "{name}", "DISABLE_PROFILER": "1", "DISABLE_STATS": "1"},
    "bookinfo": {},
}
# the system's own load generator, pointed at the ATG sidecar and stopped after two minutes
LOAD = {"online-boutique": ("loadgenerator", {"FRONTEND_ADDR": "atg-proxy:8080", "USERS": "5", "RATE": "1",
                                               "LOCUST_RUN_TIME": "2m"})}


def docs(sid: str):
    for rel in SOURCES[sid]:
        for d in yaml.safe_load_all((OSS / sid / "upstream" / rel).read_text(encoding="utf-8")):
            if d:
                yield d


def convert(sid: str) -> tuple[dict, list[str]]:
    all_docs = list(docs(sid))
    services = [d for d in all_docs if d["kind"] == "Service"]
    deployments = [d for d in all_docs if d["kind"] == "Deployment"]
    out, notes = {}, []
    for dep in deployments:
        name = dep["metadata"]["name"]
        pod = dep["spec"]["template"]
        labels = pod["metadata"].get("labels", {})
        svcs = [s for s in services if s["spec"].get("selector")
                and all(labels.get(k) == v for k, v in s["spec"]["selector"].items())]
        alias = next((s["metadata"]["name"] for s in svcs if not s["metadata"]["name"].endswith("-external")), name)
        c = pod["spec"]["containers"][0]
        env = {}
        for e in c.get("env", []) or []:
            if "value" in e:
                env[e["name"]] = str(e["value"])
        for k, v in EXTRA_ENV[sid].items():
            env.setdefault(k, v.format(name=alias))
        ports = {p["containerPort"] for p in c.get("ports", []) or []}
        for s in svcs:
            for p in s["spec"].get("ports", []):
                tp = p.get("targetPort", p["port"])
                if isinstance(tp, int) and p["port"] != tp and not s["metadata"]["name"].endswith("-external"):
                    notes.append(f"{s['metadata']['name']}: port {p['port']} -> {tp} (callers must use {tp})")
        svc = {"image": c["image"], "restart": "unless-stopped",
               "networks": {"default": {"aliases": [alias]}} if alias != name else ["default"]}
        if c.get("command"):
            svc["command"] = c["command"] + (c.get("args") or [])
        elif c.get("args"):
            svc["command"] = c["args"]
        if env:
            svc["environment"] = env
        if ports:
            svc["expose"] = [str(p) for p in sorted(ports)]
        if sid in LOAD and name == LOAD[sid][0]:
            svc = {"image": c["image"], "profiles": ["users"], "environment": LOAD[sid][1], "networks": ["default"]}
        out[name] = svc
    # callers address a remapped Service by its port; inside compose they must use the container port
    remap = {}
    for s in services:
        if s["metadata"]["name"].endswith("-external"):
            continue
        for p in s["spec"].get("ports", []):
            tp = p.get("targetPort", p["port"])
            if isinstance(tp, int) and tp != p["port"]:
                remap[f"{s['metadata']['name']}:{p['port']}"] = f"{s['metadata']['name']}:{tp}"
    for svc in out.values():
        for k, v in (svc.get("environment") or {}).items():
            svc["environment"][k] = remap.get(v, v)
    notes = [n + ", rewritten in the callers' settings" for n in notes]
    return {"name": f"real-{sid}", "services": out,
            "networks": {"default": {"name": f"{sid}-net"}}}, notes


def main() -> int:
    for sid in sys.argv[1:] or list(SOURCES):
        compose, notes = convert(sid)
        head = (f"# {sid}: the real images from its own Kubernetes manifests ({', '.join(SOURCES[sid])}),\n"
                f"# for a laptop with Docker. Generated by opensource/real/k8s2compose.py; do not edit by hand.\n")
        if notes:
            head += "# Port remaps: " + "; ".join(notes) + "\n"
        dest = HERE / sid / "docker-compose.yml"
        dest.parent.mkdir(exist_ok=True)
        dest.write_text(head + yaml.safe_dump(compose, sort_keys=False, width=120), encoding="utf-8")
        print(f"{dest.relative_to(OSS.parent)}: {len(compose['services'])} services" + (f", {len(notes)} port notes" if notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
