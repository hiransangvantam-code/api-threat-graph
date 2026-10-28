# Paper ↔ code: where each part of the proposed architecture lives

เอกสารนี้จับคู่ทุกส่วนใน Section III และ Fig. 1 ของ paper กับโค้ดที่ทำส่วนนั้น และบอกว่าจะเห็นมันทำงานได้ที่ไหน ใช้ตอบกรรมการได้ว่า "ส่วนนี้อยู่ในโค้ดตรงไหน" ท้ายเอกสารมีรายการจุดที่ paper กับโค้ดยังไม่ตรงกัน พร้อมวิธีแก้

"Running" below means the two-Docker setup started with `START-Windows.bat` / `sh start.sh`; pages are at http://localhost:8080.

## Deployment (III-A)

| Paper | Code | See it running |
|---|---|---|
| On-premise, self-hosted, deployed inside the customer's infrastructure with Docker Compose | Two Compose projects: the company's system `target/docker-compose.yml` (network `customer-net`) and the ATG platform `docker-compose.yml`, which joins `customer-net` as an external network | `docker compose ps` and `docker compose -f target/docker-compose.yml ps` |
| No source code, raw traces or telemetry leave the organisation | ATG reads only what crosses the network plus the manifests mounted read-only; the capture keeps body *shapes* and header *names*, never values (`extractor/mitm_addon.py`); nothing is sent outside `customer-net` | `output/site/scans/<scan>/raw/runtime_traffic.json` |

## Phase 1: Multi-source extractor (III-B)

| Paper | Code | See it running |
|---|---|---|
| mitmproxy as an inline sidecar or proxy listener; URIs, methods, headers, status codes | Container `atg-proxy`: `mitmdump --mode reverse:http://api-gateway:8000@8080` (inline in front of the gateway) and `--mode regular@8081` (the services' east-west proxy, `MESH_PROXY` in the target); addon `extractor/mitm_addon.py`; extractor `extractor/runtime_traffic.py` | Phase 1 report, "Runtime traffic" |
| OpenAPI discovery at `/openapi.json`, `/swagger.yaml`, `/api-docs`; schemas, DTOs, auth schemes (Bearer JWT, OAuth2) | `extractor/openapi_discovery.py` (probe list `DEFAULT_PROBE_PATHS`, security schemes in `_security_scheme_summary`); targets in `docker/extractor-target.yaml` | Phase 1 report, "OpenAPI discovery" |
| Kubernetes manifests (Service, Ingress, NetworkPolicy) and gateway definitions (Spring Cloud Gateway, Envoy); public entry points, routing rewrites, rate-limiting directives, mTLS | `extractor/infra_discovery.py`: Service, Ingress, NetworkPolicy, Secret, ConfigMap routes; Spring Cloud Gateway, nginx, Kong, Istio VirtualService (Envoy-based); rate limits from `RequestRateLimiter`, `limit_req`, Kong `rate-limiting`, nginx-ingress `limit-rps`/`limit-rpm`; mTLS from Istio `PeerAuthentication` (STRICT), `DestinationRule` and Linkerd injection | Phase 1 report, "Infrastructure & gateway"; tests `test_rate_limit_directives`, `test_mtls_enforcement` |
| Trace spans and W3C traceparent via OpenTelemetry collectors; execution paths and parent-child callers | Container `atg-collector` (official OpenTelemetry Collector, config `docker/otel-collector.yaml`): OTLP in, OTLP/JSON file out. The target services export with the standard OTLP exporter (`OTEL_EXPORTER_OTLP_ENDPOINT`), W3C traceparent is the default propagator (`demo_target/services/common.py`). Extractor `extractor/callchain_discovery.py` | Phase 1 report, "Distributed trace / call chain"; home page, "span batches" per scan |

## Phase 2: API normalizer and EUJF (III-C)

| Paper | Code | See it running |
|---|---|---|
| Numeric path segments → `/{id}`, UUIDs → `/{uuid}` | `extractor/common.py` `template_path` | `scans/<scan>/raw/runtime_traffic.json` |
| Contract reconciliation against OpenAPI templates | `atg/normalizer.py` `normalize(reconcile=True)`, function `fit` | `eujf.json` → `summary.reconciled_traffic_paths` |
| EUJF record as in Algorithm 1: `api_id`, `service`, `endpoint`, `method`, `auth`, `evidence {traffic_observed, openapi_declared, gateway_routed, confidence}` | First fields of every record in `eujf.json["endpoints"]` (`atg/normalizer.py`, end of `normalize`); the record also keeps the facts Phase 3 needs (sources, auth behaviour, data classes, inventory status) | `scans/<scan>/eujf.json` |
| Confidence: HIGH (spec and runtime), MEDIUM (proxy traffic only, shadow), ZOMBIE (documented, no runtime traffic) | `evidence.confidence` in `atg/normalizer.py` ("runtime" = proxy traffic or traces) | Dashboard → API overview, confidence bar |
| Normalized records persisted in a local PostgreSQL database | Table `atg_eujf` (`atg/graphstore.py` `save_eujf`, called by `atg/pipeline.py` right after Phase 2) | `docker compose exec atg-postgres psql -U atg -c "SELECT api_id, method, endpoint, auth, confidence FROM atg_eujf;"` |
| API inventory | `eujf.json` `endpoints` + `inventory_status` (documented / shadow / zombie / dormant) | Dashboard → API overview |

## Phase 3: Analysis and risk assessment (III-D)

| Paper | Code | See it running |
|---|---|---|
| Dependency analyzer: Span_parent(S_A, Endpoint_A) –CALLS→ Span_child(S_B, Endpoint_B) | `atg/analysis.py` `dependency_analysis`; endpoint-to-endpoint `CALLS` edges from trace chains in `build_graph` | Dashboard → Service dependencies |
| Rule engine on EUJF, gateway policies and trace attributes; OWASP API Top 10 and NIST SP 800-95; groups Token security, API OWASP Top 10, Logging and tracing | `atg/rules.py`: 27 rules in the three groups, each with OWASP, CWE, MITRE ATT&CK and NIST references | Dashboard → Rule catalog |
| Table I rows API1, API2, API7, SEC18, NIST | `TABLE_I` in `atg/rules.py`: API1 → API1, API2 → TS-01/TS-02/TS-03, API7 → API7, SEC18 → TS-07 (now also reads rate-limit directives), NIST lateral boundary → TS-08 (skips mTLS-enforced services) and API8-NETPOL | Rule catalog and findings show "Table I …" |
| Vulnerability analyzer: findings with severity, affected API and R_local = L × I (1-25) | `atg/analysis.py` `run_rules` | Dashboard → Top vulnerabilities |
| Threat graph in a PostgreSQL graph schema; edges ROUTES_TO, CALLS, QUERIES, HAS_FINDING | `atg/analysis.py` `build_graph`; tables `atg_nodes`, `atg_edges` (`atg/graphstore.py`). Edge names follow eq. (3); node types follow Fig. 1 (API, Endpoint, Dependency, Vulnerability, Risk) plus Actor | `threat-graph.html`; `SELECT rel, COUNT(*) FROM atg_edges GROUP BY rel;` |
| Attack path analysis (APCR) | Recursive SQL `ATTACK_PATH_SQL` in `atg/graphstore.py`; scoring `score_paths`, propagation `propagate`, fix plan `mitigation_plan` in `atg/analysis.py` | Dashboard → Attack paths, Recommended fixes |

## Phase 4: Output (III-E)

| Paper | Code | See it running |
|---|---|---|
| API overview: total APIs, source breakdown (OpenAPI vs traffic vs gateway), evidence confidence | `atg/dashboard.py`, section "API overview" (KPI row, confidence bar, inventory table with API IDs) | Dashboard |
| Risk summary | "Risk summary" | Dashboard |
| Top vulnerabilities ranked by R_local | "Top vulnerabilities" | Dashboard |
| Trends & insights: threat graph, APCR paths, remediation | "Attack paths", "Threat graph", "Recommended fixes", "Trend & insight"; full-screen graph page `view="graph"` | `threat-graph.html`, home page before/after table |

## Where the paper and the code still differ

| Point | Paper says | Code does | What to change |
|---|---|---|---|
| APCR | P(π) = ∏ F(v_i, v_i+1); R_path = P(π) × max I × Σ R_local, paths from ingress to data sinks | APCR = L × I × entry factor (internet 1.0, in-cluster 0.5) × 0.95 per chained call, one path per finding; R = Σ over findings of the best APCR | Paper text (decided: keep the evaluated formula). Replacement text: Section K of the Section IV draft doc |
| Graph vocabulary | Fig. 1: API, Endpoint, Dependency, Vulnerability, Risk; eq. (3): Ingress, Service, Endpoint, DBSink, Finding | Fig. 1 names plus Actor; edges use eq. (3) names plus REACHES, EXPOSES, DEPENDS_ON, RUNS_ON, USES, LEADS_TO | Make eq. (3) use the Fig. 1 names (replacement in Section K) |
| Table I values | API1 4×4, API2 5×5, API7 3×5, SEC18 4×4, NIST 3×5 | Base values: API1 3×4, TS-01/TS-02 4×4, TS-03 3×4, API7 3×4, TS-07 3×4, TS-08 2×4, API8-NETPOL 2×3; each finding then moves ±1 for exposure and data sensitivity | Update Table I (replacement in Section K) |
| The word "zombie" | ZOMBIE = documented, no runtime traffic | `evidence.confidence = ZOMBIE` follows the paper; the separate inventory label `zombie` (OWASP API9: deprecated but still called) is kept for the evaluation, and "documented, never seen" is inventory label `dormant` | Mention the two meanings in III-C, or rename the inventory label in a later version |
| Envoy | Gateway definitions such as Envoy | Envoy through Istio VirtualService; a raw Envoy bootstrap file is not parsed | Say "Envoy-based Istio routes" |
| HTTPS capture | mitmproxy intercepts HTTP/HTTPS | Works for HTTPS when clients trust mitmproxy's CA; the demo target uses HTTP inside its network | Nothing, or one sentence |
