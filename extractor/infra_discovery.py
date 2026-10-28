"""
Extractor 1c - INFRASTRUCTURE & GATEWAY DISCOVERY  (source: K8s manifests)

Reads Kubernetes YAML (any mix of files/folders, multi-document files OK)
plus gateway routing config, and records the deployment facts that decide
how exposed an API really is:

  workload        containers, images, ports, env var NAMES and where each
                  value comes from (plaintext / Secret / ConfigMap), security
                  context, resource limits
  service         type (ClusterIP / NodePort / LoadBalancer) and which
                  workloads it selects
  ingress         public host + path -> backend service
  gateway_route   path prefix -> upstream service (ConfigMap routes,
                  Istio VirtualService, Kong declarative config)
  network_policy  who is allowed to talk to whom
  secret / config names and keys only
  exposure        computed: how each workload can be reached
                  (internet via ingress -> gateway -> route, NodePort, internal)

Secret values are never written to the output. Plaintext env values are only
kept when they are URLs, because those are dependency hints
(USER_SERVICE_URL=http://user-service:8001 means order -> user).
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .common import SENSITIVE_NAME, envelope, iter_files, load_yaml_docs

SOURCE = "infrastructure"
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}


def _pod_spec(doc: dict) -> tuple[dict, dict]:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec, (doc.get("metadata") or {}).get("labels") or {}
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    tmpl = spec.get("template") or {}
    return tmpl.get("spec") or {}, (tmpl.get("metadata") or {}).get("labels") or {}


def _env_entry(e: dict) -> dict:
    name = e.get("name", "")
    if "valueFrom" in e:
        vf = e["valueFrom"]
        src = ("secretRef" if "secretKeyRef" in vf else
               "configMapRef" if "configMapKeyRef" in vf else
               "fieldRef" if "fieldRef" in vf else "other")
        ref = vf.get("secretKeyRef") or vf.get("configMapKeyRef") or {}
        return {"name": name, "source": src, "ref": ref.get("name"), "sensitive_name": bool(SENSITIVE_NAME.search(name))}
    value = str(e.get("value", ""))
    entry = {"name": name, "source": "plaintext", "sensitive_name": bool(SENSITIVE_NAME.search(name))}
    if value.startswith(("http://", "https://", "grpc://")) or (":" in value and "." not in value and " " not in value and not entry["sensitive_name"]):
        entry["value"] = value  # URL / host:port, a dependency hint, not a secret
    else:
        entry["value_length"] = len(value)
    return entry


def _container(c: dict) -> dict:
    image = c.get("image", "")
    tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else "latest(implicit)"
    sc = c.get("securityContext") or {}
    res = c.get("resources") or {}
    return {
        "name": c.get("name"),
        "image": image,
        "image_tag": tag,
        "ports": [p.get("containerPort") for p in c.get("ports", []) if p.get("containerPort")],
        "env": [_env_entry(e) for e in c.get("env", [])],
        "env_from": [
            {"secretRef" if "secretRef" in ef else "configMapRef": (ef.get("secretRef") or ef.get("configMapRef") or {}).get("name")}
            for ef in c.get("envFrom", [])
        ],
        "security_context": {k: sc[k] for k in (
            "privileged", "runAsNonRoot", "runAsUser", "readOnlyRootFilesystem",
            "allowPrivilegeEscalation", "capabilities") if k in sc},
        "resources": {"limits": bool(res.get("limits")), "requests": bool(res.get("requests"))},
        "probes": {p: p in c for p in ("livenessProbe", "readinessProbe")},
    }


def _matches(selector: dict, labels: dict) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _routes_from_configmap(doc: dict, src: str) -> list[dict]:
    out = []
    for key, text in (doc.get("data") or {}).items():
        if not key.endswith((".yaml", ".yml")):
            continue
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("routes"), list):
            for r in parsed["routes"]:
                up = r.get("upstream", "")
                out.append({
                    "kind": "gateway_route",
                    "gateway": "configmap",
                    "defined_in": f"{src} (ConfigMap {doc['metadata'].get('name')}/{key})",
                    "match_prefix": r.get("prefix"),
                    "upstream": up,
                    "upstream_service": r.get("service") or urlsplit(up).hostname,
                    "strip_prefix": r.get("strip_prefix"),
                    "auth": r.get("auth", "unspecified"),
                    "rate_limit": {"directive": f"rate_limit: {r['rate_limit']}"} if r.get("rate_limit") else None,
                })
    return out


def _routes_from_virtualservice(doc: dict, src: str) -> list[dict]:
    out = []
    spec = doc.get("spec") or {}
    for http in spec.get("http", []):
        prefixes = [((m.get("uri") or {}).get("prefix") or (m.get("uri") or {}).get("exact") or "/")
                    for m in http.get("match", [{}])]
        for dest in http.get("route", []):
            host = ((dest.get("destination") or {}).get("host") or "").split(".")[0]
            for p in prefixes:
                out.append({
                    "kind": "gateway_route", "gateway": "istio",
                    "defined_in": f"{src} (VirtualService {doc['metadata'].get('name')})",
                    "match_prefix": p, "upstream": host, "upstream_service": host,
                    "strip_prefix": (http.get("rewrite") or {}).get("uri"), "auth": "unspecified",
                    "rate_limit": None,
                })
    return out


def _routes_from_kong(doc: dict, src: str) -> list[dict]:
    out = []
    for svc in doc.get("services", []):
        up = svc.get("url") or f"{svc.get('protocol', 'http')}://{svc.get('host')}:{svc.get('port', 80)}"
        plugins = {p.get("name") for p in svc.get("plugins", [])}
        for r in svc.get("routes", []):
            rp = plugins | {p.get("name") for p in r.get("plugins", [])}
            auth = "required" if rp & {"jwt", "key-auth", "basic-auth", "oauth2", "openid-connect"} else "none"
            rl = sorted(x for x in rp if x and "rate-limiting" in x)
            for p in r.get("paths", ["/"]):
                out.append({
                    "kind": "gateway_route", "gateway": "kong", "defined_in": f"{src} (Kong service {svc.get('name')})",
                    "match_prefix": p, "upstream": up, "upstream_service": urlsplit(up).hostname,
                    "strip_prefix": p if r.get("strip_path", True) else None, "auth": auth,
                    "rate_limit": {"directive": f"Kong plugin {rl[0]}"} if rl else None,
                })
    return out


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")


def _subst(text: str, env: dict) -> str:
    """${VAR} / ${VAR:default} as used by Spring and nginx templates."""
    return _VAR.sub(lambda m: str(env.get(m.group(1), m.group(2) if m.group(2) is not None else m.group(0))), text)


def _host_service(target: str) -> str | None:
    target = target.strip().rstrip(";")
    if "://" in target:
        target = target.split("://", 1)[1]
    host = target.split("/", 1)[0].split(":", 1)[0]
    return host.split(".")[0] or None


def _routes_from_scg(path: Path, gateway_service: str | None, env: dict) -> list[dict]:
    """Spring Cloud Gateway application.yml: spring.cloud.gateway.routes[]"""
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    gw = (((doc.get("spring") or {}).get("cloud") or {}).get("gateway") or {})
    name = gateway_service or ((doc.get("spring") or {}).get("application") or {}).get("name")
    out = []
    default_rl = any("RequestRateLimiter" in str(f) for f in gw.get("default-filters", []) or [])
    for r in gw.get("routes", []) or []:
        upstream = _subst(str(r.get("uri", "")), env)
        strip = 0
        auth = "none"
        rate_limit = {"directive": "RequestRateLimiter (default-filters)"} if default_rl else None
        for f in r.get("filters", []) or []:
            f = str(f)
            if f.startswith("StripPrefix="):
                strip = int(f.split("=", 1)[1] or 0)
            if re.search(r"TokenRelay|Jwt|OAuth|Auth", f):
                auth = "required"
            if "RequestRateLimiter" in f:
                rate_limit = {"directive": "RequestRateLimiter filter"}
        for pred in r.get("predicates", []) or []:
            pred = str(pred)
            if not pred.startswith("Path="):
                continue
            for pat in pred[5:].split(","):
                pat = pat.strip()
                prefix = re.sub(r"/\*\*$", "", pat) or "/"
                segs = [x for x in prefix.split("/") if x]
                out.append({
                    "kind": "gateway_route", "gateway": "spring-cloud-gateway", "gateway_service": name,
                    "defined_in": f"{path} (route {r.get('id')})", "match_prefix": prefix, "pattern": pat,
                    "upstream": upstream, "upstream_service": _host_service(upstream.replace("lb://", "http://")),
                    "strip_prefix": "/" + "/".join(segs[:strip]) if strip else None, "auth": auth,
                    "rate_limit": rate_limit,
                })
    return out


def _routes_from_nginx(path: Path, gateway_service: str | None, env: dict) -> list[dict]:
    """nginx: location <prefix> { ... proxy_pass <url>; } (env-style ${VAR} substituted)."""
    text = _subst(path.read_text(encoding="utf-8"), env)
    out, seen = [], set()
    for m in re.finditer(r"location\s+(?:[=^~]+\s*)?(\S+)\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        block = text[m.end():i]
        pp = re.search(r"proxy_pass\s+([^;\s]+)", block)
        if not pp:
            continue
        url = pp.group(1)
        if (m.group(1), url) in seen:  # same location in the http and https server blocks
            continue
        seen.add((m.group(1), url))
        rest = url.split("://", 1)[-1]
        uri = "/" + rest.split("/", 1)[1] if "/" in rest else None
        out.append({
            "kind": "gateway_route", "gateway": "nginx", "gateway_service": gateway_service,
            "defined_in": f"{path} (location {m.group(1)})", "match_prefix": m.group(1), "pattern": m.group(1),
            "upstream": url, "upstream_service": _host_service(url),
            # proxy_pass with a URI part replaces the matched prefix with that URI
            # (strip_prefix is kept for older readers; replace_with is exact)
            "strip_prefix": m.group(1).rstrip("/") if uri else None,
            "replace_with": uri,
            "auth": "required" if re.search(r"\bauth_(request|basic|jwt)\b", block) else "none",
            "rate_limit": {"directive": rl.group(0).strip()} if (rl := re.search(r"limit_req\s+[^;]+;", block)) else None,
        })
    return out


def _configmap_env(paths) -> dict:
    env = {}
    for f in iter_files(paths or [], (".yaml", ".yml")):
        for d in load_yaml_docs(f):
            if d.get("kind") == "ConfigMap":
                env.update({k: str(v) for k, v in (d.get("data") or {}).items()})
    return env


def extract(cfg: dict, service_map: dict[str, str], run_id: str) -> dict:
    t0 = time.perf_counter()
    files = iter_files(cfg.get("manifest_paths", []), (".yaml", ".yml"))
    warnings: list[str] = []
    workloads, services, ingresses, routes, netpols, secrets, configmaps = [], [], [], [], [], [], []
    mtls_policies: list[dict] = []
    unknown_kinds: dict[str, int] = {}

    for f in files:
        src = str(f)
        docs = load_yaml_docs(f)
        if not docs:
            warnings.append(f"{src}: no YAML documents parsed")
        for doc in docs:
            if doc.get("kind") == "List":
                docs.extend(i for i in doc.get("items", []) if isinstance(i, dict))
                continue
            if "_format_version" in doc and "services" in doc:
                routes += _routes_from_kong(doc, src)
                continue
            kind = doc.get("kind")
            meta = doc.get("metadata") or {}
            ns = meta.get("namespace", "default")
            name = meta.get("name")
            if kind in WORKLOAD_KINDS:
                pod, labels = _pod_spec(doc)
                tmeta = (((doc.get("spec") or {}).get("template") or {}).get("metadata") or {})
                annotations = {**(meta.get("annotations") or {}), **(tmeta.get("annotations") or {})}
                workloads.append({
                    "kind": "workload", "workload_kind": kind, "name": name, "namespace": ns,
                    "defined_in": src, "labels": labels,
                    "replicas": (doc.get("spec") or {}).get("replicas"),
                    "service_account": pod.get("serviceAccountName", "default"),
                    "automount_service_account_token": pod.get("automountServiceAccountToken", True),
                    "host_network": bool(pod.get("hostNetwork")),
                    "pod_security_context": pod.get("securityContext") or {},
                    "containers": [_container(c) for c in pod.get("containers", [])],
                    "init_containers": [c.get("image") for c in pod.get("initContainers", [])],
                    "mesh": "linkerd" if str(annotations.get("linkerd.io/inject", "")).lower() == "enabled" else None,
                })
            elif kind == "Service":
                spec = doc.get("spec") or {}
                services.append({
                    "kind": "service", "name": name, "namespace": ns, "defined_in": src,
                    "type": spec.get("type", "ClusterIP"),
                    "selector": spec.get("selector") or {},
                    "ports": [{k: p.get(k) for k in ("name", "port", "targetPort", "nodePort", "protocol") if p.get(k) is not None}
                              for p in spec.get("ports", [])],
                })
            elif kind == "Ingress":
                spec = doc.get("spec") or {}
                tls_hosts = {h for t in spec.get("tls", []) for h in t.get("hosts", [])}
                for rule in spec.get("rules", []):
                    for p in (rule.get("http") or {}).get("paths", []):
                        be = (p.get("backend") or {}).get("service") or {}
                        ingresses.append({
                            "kind": "ingress", "name": name, "namespace": ns, "defined_in": src,
                            "host": rule.get("host", "*"), "path": p.get("path", "/"),
                            "tls": rule.get("host") in tls_hosts,
                            "backend_service": be.get("name") or (p.get("backend") or {}).get("serviceName"),
                            "backend_port": (be.get("port") or {}).get("number") or (p.get("backend") or {}).get("servicePort"),
                            "annotations": sorted((meta.get("annotations") or {}).keys()),
                            "rate_limit": next(({"directive": f"{k}: {v}"} for k, v in sorted((meta.get("annotations") or {}).items())
                                                if k.split("/")[-1] in ("limit-rps", "limit-rpm", "limit-connections")), None),
                        })
            elif kind == "NetworkPolicy":
                spec = doc.get("spec") or {}
                peers = []
                for rule in spec.get("ingress", []) or []:
                    for fr in rule.get("from", []) or []:
                        peers.append({k: (v.get("matchLabels") if isinstance(v, dict) and "matchLabels" in v else v)
                                      for k, v in fr.items()})
                netpols.append({
                    "kind": "network_policy", "name": name, "namespace": ns, "defined_in": src,
                    "pod_selector": (spec.get("podSelector") or {}).get("matchLabels") or {},
                    "policy_types": spec.get("policyTypes", ["Ingress"]),
                    "ingress_from": peers,
                })
            elif kind == "Secret":
                secrets.append({"kind": "secret", "name": name, "namespace": ns, "defined_in": src,
                                "type": doc.get("type", "Opaque"),
                                "keys": sorted({**(doc.get("data") or {}), **(doc.get("stringData") or {})})})
            elif kind == "ConfigMap":
                found = _routes_from_configmap(doc, src)
                routes += found
                configmaps.append({"kind": "configmap", "name": name, "namespace": ns, "defined_in": src,
                                   "keys": sorted((doc.get("data") or {}).keys()), "is_gateway_config": bool(found)})
            elif kind == "VirtualService":
                routes += _routes_from_virtualservice(doc, src)
            elif kind == "PeerAuthentication":  # Istio: server-side mTLS for the selected workloads
                spec = doc.get("spec") or {}
                mtls_policies.append({
                    "kind": "mtls_policy", "source": "PeerAuthentication", "name": name, "namespace": ns,
                    "defined_in": src, "selector": (spec.get("selector") or {}).get("matchLabels") or {},
                    "mode": ((spec.get("mtls") or {}).get("mode") or "UNSET").upper()})
            elif kind == "DestinationRule":  # Istio: client-side TLS towards a host
                spec = doc.get("spec") or {}
                mode = (((spec.get("trafficPolicy") or {}).get("tls") or {}).get("mode") or "").upper()
                if mode:
                    mtls_policies.append({
                        "kind": "mtls_policy", "source": "DestinationRule", "name": name, "namespace": ns,
                        "defined_in": src, "host": str(spec.get("host", "")).split(".")[0], "mode": mode})
            elif kind:
                unknown_kinds[kind] = unknown_kinds.get(kind, 0) + 1

    # --- gateway configuration files (not Kubernetes objects) -------------
    gw_inputs = []
    for g in cfg.get("gateway_configs", []) or []:
        gpath = Path(g["path"])
        if not gpath.exists():
            warnings.append(f"gateway config {gpath} not found")
            continue
        env = {**_configmap_env(g.get("env_from")), **(g.get("env") or {})}
        kind = g.get("type", "spring-cloud-gateway")
        parser = {"spring-cloud-gateway": _routes_from_scg, "nginx": _routes_from_nginx}.get(kind)
        if not parser:
            warnings.append(f"gateway config type '{kind}' not supported")
            continue
        found = parser(gpath, g.get("service"), env)
        routes += found
        gw_inputs.append(str(gpath))
        if not found:
            warnings.append(f"{gpath}: no routes found")

    # --- link things together -------------------------------------------
    for s in services:
        s["selects_workloads"] = [w["name"] for w in workloads
                                  if w["namespace"] == s["namespace"] and _matches(s["selector"], w["labels"])]
    svc_by_name = {s["name"]: s for s in services}
    workload_names = {w["name"] for w in workloads}

    for w in workloads:
        via = []
        for m in mtls_policies:
            if m["source"] == "PeerAuthentication" and m["mode"] == "STRICT" and \
                    (m["namespace"] in (w["namespace"], "istio-system")) and \
                    (not m["selector"] or _matches(m["selector"], w["labels"])):
                via.append(f"PeerAuthentication {m['name']} (STRICT)")
        if w.get("mesh") == "linkerd":
            via.append("Linkerd proxy injected (automatic mTLS)")
        w["mtls"] = {"enforced": bool(via), "via": via}
        w["network_policies"] = [n["name"] for n in netpols
                                 if n["namespace"] == w["namespace"] and
                                 (not n["pod_selector"] or _matches(n["pod_selector"], w["labels"]))]
        for c in w["containers"]:
            for e in c["env"]:
                host = urlsplit(e["value"]).hostname if "://" in e.get("value", "") else e.get("value", "").split(":")[0] or None
                if host and host.split(".")[0] in svc_by_name:
                    e["references_service"] = host.split(".")[0]

    exposure = []
    gateway_workloads = set()
    for ing in ingresses:
        svc = svc_by_name.get(ing["backend_service"])
        for wname in (svc or {}).get("selects_workloads", []):
            gateway_workloads.add(wname)
            exposure.append({"kind": "exposure", "workload": wname, "level": "internet",
                             "via": [f"Ingress {ing['name']} {ing['host']}{ing['path']}", f"Service {svc['name']}"],
                             "tls": ing["tls"]})
    # a gateway named by its route config and published by NodePort/LoadBalancer is an edge too
    for r in routes:
        gs = r.get("gateway_service")
        if gs and not gateway_workloads:
            for s in services:
                if s["type"] in ("NodePort", "LoadBalancer") and gs in s["selects_workloads"]:
                    gateway_workloads.add(gs)
    for r in routes:
        svc = svc_by_name.get(r["upstream_service"])
        for wname in (svc or {}).get("selects_workloads", []):
            if gateway_workloads:
                exposure.append({"kind": "exposure", "workload": wname, "level": "internet",
                                 "via": [f"gateway route {r['match_prefix']} (auth: {r['auth']})", f"Service {svc['name']}"],
                                 "gateway_auth": r["auth"]})
    for s in services:
        if s["type"] in ("NodePort", "LoadBalancer"):
            for wname in s["selects_workloads"]:
                exposure.append({"kind": "exposure", "workload": wname,
                                 "level": "node" if s["type"] == "NodePort" else "internet",
                                 "via": [f"Service {s['name']} type={s['type']} " +
                                         ",".join(str(p.get('nodePort', p.get('port'))) for p in s["ports"])]})
    for w in workloads:
        if w["host_network"]:
            exposure.append({"kind": "exposure", "workload": w["name"], "level": "node", "via": ["hostNetwork: true"]})
    exposed = {e["workload"] for e in exposure}
    for w in workloads:
        if w["name"] not in exposed:
            exposure.append({"kind": "exposure", "workload": w["name"], "level": "internal", "via": ["cluster network only"]})

    for r in routes:
        if r["upstream_service"] not in svc_by_name and r["upstream_service"] not in workload_names:
            warnings.append(f"gateway route {r['match_prefix']} points at '{r['upstream_service']}', which no manifest defines")

    records = workloads + services + ingresses + routes + netpols + secrets + configmaps + mtls_policies + exposure
    plaintext_sensitive = sum(1 for w in workloads for c in w["containers"] for e in c["env"]
                              if e["source"] == "plaintext" and e["sensitive_name"])
    stats = {
        "files": len(files),
        "workloads": len(workloads),
        "services": len(services),
        "ingress_paths": len(ingresses),
        "gateway_routes": len(routes),
        "network_policies": len(netpols),
        "mtls_policies": len(mtls_policies),
        "rate_limited_routes": sum(1 for r in routes if r.get("rate_limit")),
        "secrets": len(secrets),
        "internet_exposed_workloads": sorted({e["workload"] for e in exposure if e["level"] == "internet"}),
        "node_exposed_workloads": sorted({e["workload"] for e in exposure if e["level"] == "node"}),
        "workloads_without_network_policy": sorted(w["name"] for w in workloads if not w["network_policies"]),
        "plaintext_env_with_sensitive_name": plaintext_sensitive,
        "ignored_kinds": unknown_kinds,
    }
    return envelope(SOURCE, "k8s-manifest-parser", run_id, [str(f) for f in files] + gw_inputs, records, stats,
                    warnings, (time.perf_counter() - t0) * 1000)
