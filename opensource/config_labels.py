"""
Configuration weaknesses of an open-source system, computed from its own deployment files.

These are the labels nobody has to argue about: does a container set runAsNonRoot, does it have
memory limits, is a password written into the file. The checks are plain field tests, written
for this benchmark and independent of ATG's extractor and rules, so the ground truth is not
ATG's own output. Each label says which file it comes from.

Categories (the same ones docs/BENCHMARK_OSS.md uses for every tool):
  C1  container may run as root (no runAsNonRoot, or runAsUser 0)
  C2  privileged container
  C3  no CPU or memory limit
  C4  mutable image tag (none, or latest)
  C5  service published outside the cluster that is not meant to be public
      (NodePort / LoadBalancer, or a published compose port)
  C6  no network segmentation (no NetworkPolicy selects it; all compose services on one network)
  C7  secret value written in the deployment files (env value, ConfigMap key, committed Secret)
  C8  public entry without TLS
  C9  missing container hardening (read-only root filesystem, dropped capabilities,
      allowPrivilegeEscalation: false)
  C10 service account token mounted although nothing needs it
  O1  service publishes no API document, and none is in the repository
  O2  service sends no traces
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
SECRET_NAME = re.compile(r"(passw|secret|api[_-]?key|token|private[_-]?key|credential)", re.I)
DATASTORE = re.compile(r"(mongo|redis|mysql|postgres|-db$|db-|memcached|kafka|zookeeper|consul|jaeger|rabbitmq|"
                       r"activemq|queue|dynamodb|cdc|zipkin|prometheus|grafana)", re.I)


def _docs(paths):
    for p in paths:
        files = sorted(p.rglob("*.y*ml")) if p.is_dir() else [p]
        for f in files:
            try:
                for d in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                    if isinstance(d, dict):
                        yield f, d
            except (yaml.YAMLError, UnicodeDecodeError):
                continue


def _pod(d):
    spec = d.get("spec") or {}
    if d["kind"] == "Pod":
        return spec, (d.get("metadata") or {}).get("labels") or {}
    if d["kind"] == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    t = spec.get("template") or {}
    return t.get("spec") or {}, (t.get("metadata") or {}).get("labels") or {}


def _lab(cat, target, why, f, root):
    return {"cat": cat, "target": target, "at": target.split(":", 1)[1], "why": why,
            "evidence": str(f.relative_to(root)) if f else "", "source": "deployment files"}


def k8s_labels(s: dict, root: Path) -> tuple[list[dict], dict]:
    docs = list(_docs([root / p for p in s["artifacts"].get("manifests", [])]))
    out = []
    workloads, services, netpols = [], [], []
    for f, d in docs:
        k = d.get("kind")
        if k in WORKLOADS:
            workloads.append((f, d))
        elif k == "Service":
            services.append((f, d))
        elif k == "NetworkPolicy":
            netpols.append(d)
        elif k == "ConfigMap":
            for key, val in (d.get("data") or {}).items():
                if SECRET_NAME.search(key) and str(val).strip() and not str(val).startswith("$"):
                    out.append(_lab("C7", f"configmap:{d['metadata']['name']}", f"ConfigMap key {key} holds a secret value.", f, root))
                    break
        elif k == "Secret" and (d.get("data") or d.get("stringData")):
            out.append(_lab("C7", f"secret:{d['metadata']['name']}", "A Secret with its values is committed to the repository.", f, root))
        elif k == "Ingress":
            tls = {h for t in (d.get("spec") or {}).get("tls", []) or [] for h in t.get("hosts", [])}
            for rule in (d.get("spec") or {}).get("rules", []) or []:
                if rule.get("host") not in tls or not tls:
                    for p in (rule.get("http") or {}).get("paths", []):
                        be = ((p.get("backend") or {}).get("service") or {}).get("name") or (p.get("backend") or {}).get("serviceName")
                        if be:
                            out.append(_lab("C8", f"svc:{be}", "Ingress without TLS.", f, root))
    # Service name -> the workload names it selects (a Service can front several versions)
    aliases: dict[str, list[str]] = {}
    for f, sv in services:
        sel = (sv.get("spec") or {}).get("selector") or {}
        names = [w["metadata"]["name"] for _, w in workloads if sel and all(_pod(w)[1].get(a) == b for a, b in sel.items())]
        aliases[sv["metadata"]["name"]] = names
    public = set(s.get("public_by_design", [])) | ({s["edge"]} if isinstance(s.get("edge"), str) else set(s.get("edge") or []))
    if s.get("gateway"):
        public.add(s["gateway"]["name"])
    for f, sv in services:
        spec = sv.get("spec") or {}
        name = sv["metadata"]["name"]
        if spec.get("type") in ("NodePort", "LoadBalancer"):
            fronted = aliases.get(name) or [name]
            if not any(n in public or name in public or n.split("-v")[0] in public for n in fronted) and \
                    not name.endswith("-external"):
                out.append(_lab("C5", f"svc:{name}", f"Service type {spec['type']} publishes it outside the cluster.", f, root))
            elif spec.get("type") == "LoadBalancer" and not any(str(p.get("port")) == "443" for p in spec.get("ports", [])):
                target = (aliases.get(name) or [name])[0]
                out.append(_lab("C8", f"svc:{_svc_of(target, aliases)}", "LoadBalancer serves plain HTTP.", f, root))
    for f, w in workloads:
        name = w["metadata"]["name"]
        svc = _svc_of(name, aliases)
        pod, labels = _pod(w)
        psc = pod.get("securityContext") or {}
        cs = pod.get("containers") or []
        t = f"svc:{svc}"
        if any((c.get("securityContext") or {}).get("runAsUser") == 0 for c in cs) or psc.get("runAsUser") == 0 or \
                not (psc.get("runAsNonRoot") or all((c.get("securityContext") or {}).get("runAsNonRoot") for c in cs)):
            out.append(_lab("C1", t, "Nothing stops the container from running as root.", f, root))
        if any((c.get("securityContext") or {}).get("privileged") for c in cs):
            out.append(_lab("C2", t, "Privileged container.", f, root))
        if any(not ((c.get("resources") or {}).get("limits")) for c in cs):
            out.append(_lab("C3", t, "No CPU/memory limits.", f, root))
        for c in cs:
            img = str(c.get("image", ""))
            tag = img.rsplit(":", 1)[1] if ":" in img.rsplit("/", 1)[-1] else ""
            if (not tag or tag == "latest") and "@sha256" not in img:
                out.append(_lab("C4", t, f"Image {img} has no fixed tag.", f, root))
                break
        if not any(all(labels.get(a) == b for a, b in ((n.get("spec") or {}).get("podSelector") or {}).get("matchLabels", {}).items())
                   for n in netpols):
            out.append(_lab("C6", t, "No NetworkPolicy selects it.", f, root))
        for c in cs:
            for e in c.get("env", []) or []:
                if "value" in e and SECRET_NAME.search(str(e.get("name", ""))) and str(e["value"]).strip():
                    out.append(_lab("C7", t, f"env {e['name']} has a literal value.", f, root))
                    break
        if any(not ((c.get("securityContext") or {}).get("readOnlyRootFilesystem")) or
               "ALL" not in (((c.get("securityContext") or {}).get("capabilities") or {}).get("drop") or []) or
               (c.get("securityContext") or {}).get("allowPrivilegeEscalation") is not False for c in cs):
            out.append(_lab("C9", t, "Missing hardening: read-only root filesystem, dropped capabilities or no privilege escalation.", f, root))
        if pod.get("automountServiceAccountToken") is not False:
            out.append(_lab("C10", t, "Service account token mounted.", f, root))
    return out, aliases


def _svc_of(workload: str, aliases: dict) -> str:
    if workload in aliases.get(workload, []):   # a Service with the workload's own name selects it
        return workload
    for svc, names in aliases.items():
        if workload in names:
            return svc
    return workload


def compose_labels(s: dict, root: Path) -> list[dict]:
    f = root / s["artifacts"]["compose"]
    d = yaml.safe_load(f.read_text(encoding="utf-8"))
    out = []
    public = {s["gateway"]["name"]} if s.get("gateway") else set()
    public |= ({s["edge"]} if isinstance(s.get("edge"), str) else set(s.get("edge") or []))
    # flat: every service on the same network(s), the compose default included (nothing separates them)
    nets = {frozenset(sv.get("networks") or ["default"]) for sv in d["services"].values()}
    flat = len(nets) <= 1
    for name, sv in d["services"].items():
        t = f"svc:{name}"
        lim = ((sv.get("deploy") or {}).get("resources") or {}).get("limits") or sv.get("mem_limit") or sv.get("cpus")
        if not lim:
            out.append(_lab("C3", t, "No CPU/memory limits.", f, root))
        img = str(sv.get("image", ""))
        if img and "$" not in img:
            tag = img.rsplit(":", 1)[1] if ":" in img.rsplit("/", 1)[-1] else ""
            if not tag or tag == "latest":
                out.append(_lab("C4", t, f"Image {img} has no fixed tag.", f, root))
        if sv.get("ports") and name not in public:
            out.append(_lab("C5", t, f"Ports {sv['ports']} are published on the host.", f, root))
        if flat:
            out.append(_lab("C6", t, "All services share one network.", f, root))
        if sv.get("privileged"):
            out.append(_lab("C2", t, "Privileged container.", f, root))
        user = sv.get("user")
        if user is None or str(user).split(":")[0] in ("0", "root"):
            out.append(_lab("C1", t, "No non-root user: is set, so the image decides (often root).", f, root))
        sec = [str(x) for x in sv.get("security_opt") or []]
        if not (sv.get("read_only") and "ALL" in (sv.get("cap_drop") or []) and any("no-new-privileges" in x for x in sec)):
            out.append(_lab("C9", t, "Missing hardening: read_only, cap_drop: [ALL] or no-new-privileges.", f, root))
        env = sv.get("environment") or {}
        items = env.items() if isinstance(env, dict) else [tuple(x.split("=", 1)) if "=" in x else (x, "") for x in env]
        for k, v in items:
            if SECRET_NAME.search(str(k)) and v and not str(v).startswith("$"):
                out.append(_lab("C7", t, f"environment {k} has a literal value.", f, root))
                break
    return out


def config_labels(s: dict, root: Path) -> list[dict]:
    if not root.exists():
        raise SystemExit(f"{root} is missing: run python opensource/fetch.py first")
    out = []
    if s["artifacts"].get("manifests"):
        out += k8s_labels(s, root)[0]
    if s["artifacts"].get("compose"):
        out += compose_labels(s, root)
    # API documents and traces, for the application services
    files = {f.get("service") for f in s["artifacts"].get("spec_files", [])}
    live = set((s.get("spec") or {}).get("services", []))
    for name, sv in s["services"].items():
        if DATASTORE.search(name):
            continue
        if name not in files | live:
            out.append({"cat": "O1", "target": f"svc:{name}", "at": name, "why": "No API document, live or in the repository.",
                        "evidence": "", "source": "deployment files"})
        if not sv.get("traced", s.get("traced", True)):
            out.append({"cat": "O2", "target": f"svc:{name}", "at": name, "why": "Sends no traces as shipped.",
                        "evidence": "", "source": "deployment files"})
    return out
