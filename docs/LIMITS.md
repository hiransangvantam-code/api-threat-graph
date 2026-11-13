# Limits: what ATG cannot find, and how large a system it can handle

This file answers "what are the limits of the test". There are three kinds of limit: what a passive design review cannot see at all, how large a system the prototype handles before it gets too slow, and what the evaluation itself does not show.

## 1. What it cannot detect

ATG is passive. It reads traffic that already happens, the OpenAPI documents, the deployment manifests and the traces, and it never sends an attack request. That keeps it safe to run next to a production system, and it also decides what it can find.

### By OWASP API Security Top 10 (2023)

| Category | Rules | What ATG catches | What it misses, and why |
|---|---|---|---|
| API1 Broken object level authorization | API1 | An authenticated endpoint with an object ID in the path that never answered 403 | IDs in the query string or body (ShopLite `GET /orders?user_id=`). It cannot prove the hole exists, because that needs two accounts and an attack request, so these findings are "possible BOLA". |
| API2 Broken authentication | TS-01, TS-02, TS-03, TS-06, TS-07, TS-08 | Sensitive operations that answer anonymous callers, gateway routes without auth, declared auth not enforced, credentials in URLs, logins without visible brute-force protection, unauthenticated service-to-service calls | Weak signing secrets (ShopLite's JWT secret): ATG never copies secret values, by design. Token forgery (crAPI #15). TS-07 counts 401/403 as failed logins, so an OTP check that answers 500 slips through (crAPI #3). |
| API3 Broken object property level authorization | API3 | Bulk sensitive data from anonymous or shadow endpoints | Over-exposure to logged-in users (crAPI #4, #5), and mass assignment, for which there is no rule (crAPI #8-10, ShopLite `POST /orders` trusting `user_id`). |
| API4 Unrestricted resource consumption | API4, TS-07 | Internet-reachable services with no CPU/memory limits; logins with no rate limit | Abuse through request content, such as a repeat count field (crAPI #6). |
| API5 Broken function level authorization | API5 | Admin functions reachable by anonymous or ordinary callers | A gap for logged-in users when the endpoint also answered 401 to anonymous calls (crAPI #7, reported through API1 instead). |
| API6 Unrestricted access to sensitive business flows | none | – | Needs knowledge of the business, which none of the four sources has. |
| API7 Server side request forgery | API7 | Request fields typed or named as URLs | URL fields with other names (crAPI #11, `mechanic_api`). |
| API8 Security misconfiguration | TS-04, TS-05, API8-DEBUG, -PRIV, -ROOT, -NODEPORT, -NETPOL, -TAG, LT-04 | Plaintext secrets, missing TLS, debug endpoints, privileged or root containers, NodePorts, missing NetworkPolicy, mutable image tags, server errors | Response headers (CSP, X-Content-Type-Options and so on), CORS and TLS settings. ZAP finds these (`docs/COMPARISON_ZAP.md`). |
| API9 Improper inventory management | API9-SHADOW, -ZOMBIE, -NOSPEC, LT-01, LT-02, LT-03 | Shadow and zombie endpoints, services without a spec, untraced callers and workloads | Endpoints that receive no traffic during the review and are in no spec (see section 2). |
| API10 Unsafe consumption of APIs | API10 | Calls to third-party APIs seen in traces | Whether the response from that API is validated. That is code behaviour. |
| Injection, LLM attacks | none | – | SQL/NoSQL injection, prompt injection and similar need payloads (crAPI #12, #13, #16-18). Out of scope for a passive review. Use an active scanner such as ZAP for these. |

On ShopLite, 37 of the 40 planted weaknesses fall in what ATG can see, and it finds 36.6 of them on average under full capture (Table 16). On OWASP's own crAPI list, 12 of 18 are visible to a passive tool at all (Table 15).

### What it needs to see

- **Only what is used is found.** An endpoint that no one calls during the review and that no spec lists stays invisible. On Train Ticket, traffic alone found 32% of the endpoints after 100 requests and 83% after 2,000 (Table 10). The specs and manifests close most of that gap, with all four sources at 96-98%.
- **Untraced services hide dependencies.** If a service sends no spans, its calls to other services are known only from traffic and config (condition C2 in Section IV).
- **Gateway-only capture hides east-west calls.** Rules such as TS-08 need the sidecar on the service-to-service path.

### Protocols and inputs

- HTTP/1.1 and HTTP/2 through mitmproxy. gRPC calls show up as endpoints (service and method), but their protobuf messages stay opaque. WebSocket messages after the upgrade are not read.
- When services encrypt their calls to each other with mTLS end to end, the sidecar cannot read them unless it is the TLS endpoint. The mTLS policy itself is still read from the manifests.
- Manifests: plain Kubernetes YAML (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod, Service, Ingress, NetworkPolicy, Secret, ConfigMap), Istio PeerAuthentication, DestinationRule and VirtualService, Spring Cloud Gateway, nginx and Kong declarative config. Helm charts and Kustomize overlays have to be rendered to YAML first (`helm template`, `kubectl kustomize`).
- One network at a time: one review covers the services that the sidecar and the Collector can see.

## 2. How large a system it handles

Measured with `bench/stress.py` (Tables 21 and 22 in `results/stress/tables.md`, figure `results/figures/fig_stress.png`). The EUJF of one real ShopLite scan is cloned k times behind one gateway, so every copy has real findings and paths, and then Phases 3 and 4 run on PostgreSQL as in the Docker version. Phase 1 and Phase 2 scaling with traffic volume is Table 9 (linear, 160,000 flows in 17 s).

| | Version 1.2 | Version 1.3 |
|---|---|---|
| 31 services, 111 endpoints | Phase 3: 6.9 s | 0.4 s |
| 61 services, 221 endpoints | 57 s | 0.9 s |
| 151 services, 551 endpoints | stopped after 5 min | 4.5 s |
| 301 services, 1,101 endpoints, 11,408 attack paths | not run | 20.7 s, 226 MB peak memory |
| 31 services, 2 random calls per endpoint | 174 s | 6.2 s |
| 31 services, 3 random calls per endpoint (12,813 attack paths) | not run | 23 s, 919 MB peak memory |
| 31 services, 4 random calls per endpoint | not run | fails: the attack path query needs more than 4 GB of temporary space |

What the test found and what was changed:

- **The fix planner was the first limit.** It scored every remaining action against every remaining path at every step, so its time grew with actions × actions × paths: 55 s at 61 services. Version 1.3 scores an action only on the findings it touches. It gives exactly the same plan, checked on all ten recorded ShopLite runs, five larger synthetic systems and 300 random inputs built to have ties (`tests/test_plan.py`), and it takes 0.5 s at 61 services.
- **PostgreSQL had no statistics on the freshly created tables**, so it planned the recursive attack path query blind. Version 1.3 runs `ANALYZE` after loading the graph (a few milliseconds). The query got 12 to 52 times faster with identical paths, for example 98 s to 1.9 s at 2 calls per endpoint.
- **The limit that remains is call-chain density.** The query enumerates every simple path of up to 9 hops, and that number grows exponentially with how many services each endpoint calls. With 31 services it is fine up to about 3 calls per endpoint (23 s) and fails at 4. Most of what the planner and the dashboard use is one best path per entry point and finding, so a k-best-paths query instead of full enumeration would remove this limit. That is future work.
- **The dashboard grows with the system.** It is 1.6 MB at 31 services and 15.5 MB at 301 services. Browsers open it, but the threat graph drawing gets hard to read beyond about a hundred services. The exports (GraphML, JSON) are the better way to look at a graph that large.
- **The in-memory buffers hold about a million flows** (1 GB each, `docs/DATA_HANDLING.md`). Scan more often on a busy system.

For scale: Train Ticket, the largest real system in Section IV, has 45 services and 272 endpoints.

Test machine: 2 CPU cores and 8 GB of memory, PostgreSQL 16 in Docker on the same host. Each configuration ran once in a fresh process with fresh tables, stopped after 5 minutes.

## 3. What the evaluation does not show

From `docs/EXPERIMENT.md`, "Threats to validity":

- Train Ticket and crAPI ran as replicas with no business logic, so rules that read response content could not fire there. ShopLite is real code.
- The workload is synthetic (Zipf popularity, fixed rates).
- Everything ran on one host, so latency figures include CPU contention and callers cannot be told apart by IP address.
- The same team wrote the tool, the ground-truth miners and ShopLite's planted list. crAPI's list comes from OWASP, which is the independent check.
- The tool was fixed during the evaluation (nine bugs, Table 20). A system nobody looked at during development would be a stronger test.
- ZAP is the only other tool compared so far (`docs/COMPARISON_ZAP.md`), and only on ShopLite.
