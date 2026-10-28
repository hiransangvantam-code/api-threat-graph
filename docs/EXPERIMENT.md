# Evaluation method (Phases 1-4)

How the numbers in `results/` were produced, written so someone else can rerun them and argue with them. Results: `results/tables.md`, figures in `results/figures/`.

## What is measured

| Question | Metric | Computed in |
|---|---|---|
| RQ1 Does combining four sources find more of the API than any single source? | M1: recall, strict precision, F1 for all 15 source subsets | `bench/evaluate.py` |
| RQ2 Are duplicates merged and paths normalized? | M2: raw flows to inventory entries, duplicates collapsed, unresolved path fragments, with and without contract reconciliation | `bench/evaluate.py` |
| RQ3 Are runtime properties observed correctly? | M3: service attribution, auth enforcement, inventory label, shadow-API precision and recall | `bench/evaluate.py` |
| RQ4 Are service dependencies found? | M4: edge precision and recall | `bench/evaluate.py` |
| RQ5 Is the threat model built from extracted data the one the system really has? | T1-T3: findings, attack paths and risk ranking, tool vs oracle | `bench/evaluate_threat.py`, `bench/oracle.py` |
| RQ6 Which sources does the threat model need? | T5: finding F1 against the oracle for source subsets | `bench/evaluate_threat.py` |
| RQ7 Do the rules catch known vulnerabilities? | T6: OWASP crAPI's own challenge list; ShopLite's built-in weaknesses | `bench/evaluate_threat.py` |
| RQ8 Does applying the fixes reduce risk as the plan says? | ShopLite vulnerable vs hardened build: measured vs predicted reduction of attack-path risk | `bench/evaluate_threat.py` |
| RQ9 What does it cost? | M5 / T7: time and memory per phase, capture overhead, scaling, SQLite vs PostgreSQL | `bench/timed.py`, `bench/run_experiment.py`, `bench/run_threat.py` |

Source codes used everywhere: **O** OpenAPI, **T** runtime traffic (mitmproxy), **K** Kubernetes manifests plus gateway route config, **C** OpenTelemetry traces (call chain).

## Testbeds

| Testbed | What runs | Ground truth from |
|---|---|---|
| ShopLite | the real FastAPI services in `demo_target/` (vulnerable build, plus the hardened build for RQ8) | `bench/testbeds/shoplite/topology.yaml`, written by hand from the service code |
| Train Ticket (FudanSELab, commit `313886e99b`) | an API-surface replica: 44 services plus the gateway | `bench/miners/trainticket.py` reads the Spring controllers, security configs, `RestTemplate` call sites and the Spring Cloud Gateway route file |
| crAPI (OWASP, commit `b5fc307f3e`) | an API-surface replica: 5 services plus the nginx gateway | `bench/miners/crapi.py` reads the Spring, Django and Go route definitions, auth filters and call sites; compared against crAPI's own published OpenAPI file |

Why replicas: this environment cannot pull container images or Maven/Go dependencies, so the original systems cannot be built here. A replica (`bench/replica.py`) serves exactly the mined routes, answers 401 where the original's security config requires a token, makes the mined downstream calls, emits OpenTelemetry spans with `http.route` templates, and serves `/v2/api-docs` only for services whose original enables Swagger. It does not reproduce business logic and returns generic response bodies. `realcheck/` is a kit to repeat the Phase 1 measurement on the real crAPI in Docker; it has not been run yet.

## Ground truth

Ground truth never comes from the tool under test:

1. `topology.yaml`: every endpoint (method, path, auth, documented, deprecated), every call site, every gateway route.
2. Each service's own access log for the run (`gt/*.jsonl`): which endpoints served a request, the real caller (a bench-only header the services add), the status, and whether a credential was sent. The extractors never read these files.

## Conditions and workload

| Condition | Capture | Traces |
|---|---|---|
| C1 ideal | north-south (reverse proxy in front of the gateway) and east-west (every service calls through a mesh listener) | every service |
| C2 realistic | north-south only | about 70% of services; the untraced 30% are drawn per seed and do not propagate trace context |

Workload (`bench/workload.py`): client sessions through the gateway, touching 80% of the public endpoints, Zipf-like popularity, at least two requests per touched endpoint, 10% of requests without a credential, and an in-cluster job calling 30% of the internal-only endpoints. Train Ticket gets 3,000 requests per run, crAPI 1,500, ShopLite its own `traffic_generator.py` (40 rounds). Five seeds per testbed and condition: 30 runs.

## Phase 1 metrics

- **Match rule.** An inventory entry matches a true endpoint when the method is equal and the path shape is equal with parameter names ignored, at the backend path or at its public path through the gateway.
- **Recall (all)**: found / all true endpoints. **Recall (observable)**: found / endpoints that are documented or received traffic in the run (no passive source can see the rest). **Recall (exercised)**: found / endpoints that received traffic.
- **Strict precision**: distinct true endpoints found / inventory entries. A second entry for the same endpoint counts as a false positive.
- **Fragment**: an unmatched entry whose path still contains a concrete value one true endpoint's pattern accepts.
- **Auth decided / accuracy**: decided when traffic held anonymous requests; accuracy on decided endpoints against the source-code auth.
- **Labels**: documented, dormant (spec only), shadow (seen, in no spec), zombie (deprecated, still served).
- **Edges**: precision and recall over the source-code call graph plus gateway-to-backend edges.

## Phases 2-4: the oracle threat model

The rules, the threat graph, the attack-path search, APCR and the mitigation plan are deterministic functions of the EUJF (Phase 2 output). To measure how much the threat model suffers from what Phase 1 did not see or got wrong, `bench/oracle.py` builds the EUJF a perfect Phase 1 and Phase 2 would have produced for the same run, and Phase 3 runs on it with exactly the same code:

| Oracle part | Taken from |
|---|---|
| endpoints, inventory status | topology (documented endpoints, and every endpoint that served a request in the run) |
| traffic, auth behaviour | the access logs: every request once, real caller, real status, credential or not |
| traces, call chains, unidentified callers | which services were instrumented in the run, and the real caller of every request |
| dependencies | call edges that carried traffic, plus gateway routes |
| deployment config (services, routes, ingress, secrets) | the manifests, through the tool's own parse (identical in every condition) |
| response content (data classes, owner fields, collections, request fields) | the C1 capture of the same seed (topology files do not describe bodies; replicas return generic bodies, so these are empty there) |

Because the oracle reuses the spec documents, the manifest parse and the C1 content, agreement under C1 means "no implementation error under full visibility". It does not mean the rules are right; RQ7 tests that against vulnerability lists.

## Phase 3 metrics

- **Finding match**: same rule and same target. Target = the true endpoint (tool endpoints are mapped to ground truth with the Phase 1 match rule) or the service; service-level rules that fire several times per service also match on route prefix (TS-02) or variable name (TS-04).
- **Finding precision / recall / F1** against the oracle's findings; recall on the oracle's critical and high findings; share of matched findings with the same severity.
- **Attack paths**: precision and recall over (entry actor, finding) pairs.
- **Risk**: R (sum over findings of the best APCR among the paths reaching it), tool R / oracle R; overlap of the ten findings ranked highest by APCR; Spearman rank correlation of the propagated risk of every service; fixes the plan needs for 70% of R.
- **Ablation**: findings from Phases 2-3 on a subset of the Phase 1 files, scored against the same oracle (rules only, no attack paths).
- **Known vulnerabilities**: crAPI's 18 challenges (`docs/challenges.md` in the crAPI repo) mapped to the endpoint each is about (from `docs/challengeSolutions.md` and the source) and to the rule family that would report it; a challenge counts as detected when that rule fires on that endpoint. ShopLite: the 37 weaknesses built into the vulnerable build (`tests/test_pipeline.py`) plus three that no rule covers.
- **Hardening**: the same seed and condition run on ShopLite's hardened build; findings left, attack paths, R before and after, against the vulnerable run's own mitigation plan.
- **Timing**: Phase 2 normalize, rule engine, graph build and store, attack-path query, Phase 3 total, dashboard build and size; SQLite vs PostgreSQL on the same EUJF (identical paths and query time).

## Extra experiments (Phase 1)

- `overhead`: the same workload straight to the gateway, through the north-south proxy, and through north-south plus east-west capture; 3 repetitions; latency p50/p95 and throughput.
- `scale`: one C1 capture multiplied ×1, ×5, ×10, ×20 with fresh IDs and trace ids in every copy; time and peak memory of Phase 1 and Phase 2.
- `curve`: recall as the workload grows from 100 to 8,000 requests, pure Zipf sampling, 3 seeds.

## Reproduce

```bash
python bench/run_experiment.py grid            # Phase 1: 30 runs, about 10 minutes
python bench/run_experiment.py hardened        # ShopLite hardened build, same seeds
python bench/run_experiment.py overhead --testbed trainticket
python bench/run_experiment.py overhead --testbed crapi
python bench/run_experiment.py scale    --testbed trainticket
python bench/run_experiment.py curve    --testbed trainticket
python bench/run_threat.py grid                # Phases 2-4 vs oracle, about 10 minutes
python bench/run_threat.py hardened
python bench/run_threat.py stores              # needs PostgreSQL (ATG_GRAPH_STORE_PG or --pg)
python bench/run_threat.py dashboards
python bench/report.py                         # results/tables.md, results/tables/*.csv, results/figures/*.png
```

The miners need the two upstream checkouts at the pinned commits (`python bench/miners/trainticket.py PATH_TO_CHECKOUT`, same for `crapi.py`). Their output is committed in `bench/testbeds/`.

## Changes made to the tool during the evaluation

The tool was changed while being evaluated. Every change is a general fix, but readers should know the tool was touched while looking at these testbeds.

Found by Phase 1 pilot runs (fixed before any reported Phase 1 run):

1. Path templating turned literal words containing a digit (`travel2service`) into `{id}`. The identifier rule now also needs a digit share of at least 25% or several letter/digit switches.
2. The normalizer chose the gateway alphabetically among Ingress-exposed workloads. It now prefers the workload the gateway route config names.
3. An endpoint seen only through the gateway crashed the normalizer.
4. Duplicate spans (an exporter retry) made the call-chain walk fan out until memory ran out. The trace extractor now drops duplicates.

Found by comparing the tool's threat model with the oracle (v1 = before, v1.1 = after; Table 20 reports both, scored against the same oracle). No rule's intent or thresholds changed; the fixes change what evidence reaches the rules (and, for LT-03, which capture point it reads):

5. nginx `proxy_pass` with a URI replaces the location prefix; it was modelled as a strip, so a route like `/.well-known/jwks.json` claimed every identity endpoint as its own. Routes now carry `replace_with`.
6. Bodies, credentials and status codes seen at the gateway (north-south) were dropped whenever the backend itself was not captured, so with gateway-only capture no endpoint had data classes and rules that read them went silent. The normalizer now falls back to gateway evidence (`status_observed`, shapes, authenticated calls).
7. LT-03 (traffic without traces) looked at backend capture only; it now also counts gateway capture, except requests the gateway itself rejected.
8. `anonymous_success_internal` counted anonymous requests the gateway had forwarded as service-to-service calls (both capture points see them), which made TS-08 fire on public endpoints. It now subtracts the gateway's share.
9. LT-01 ("calls from an unidentified internal caller") treated every trace that starts at a backend as not having come through the gateway. That holds only when the gateway emits spans; with an uninstrumented gateway (crAPI's nginx) every public request looked like an unknown internal caller. Endpoints that receive public traffic behind an untraced gateway are no longer flagged.

## Threats to validity

- **Replicas, not the real systems.** No business logic and generic response bodies: rules that read response content (API3, the data-sensitivity part of TS-01 and API1) cannot fire on Train Ticket or crAPI here. ShopLite (real code) exercises them. The `realcheck/` kit (not run yet) covers Phase 1 on the real crAPI; a Phases 1-3 run on the real system is still needed for those rules.
- **The miners can be wrong.** They are regex-based readers of Java, Python and Go. The crAPI miner is cross-checked against crAPI's own spec; the real-system check lists every observed path the ground truth lacks.
- **The oracle shares parts with the tool.** Spec documents, manifest parsing and C1 response content are reused, so errors there are invisible to T1-T5. RQ7 and RQ8 test the rules against outside lists and a real fix instead.
- **Known-vulnerability mapping by us.** OWASP wrote the crAPI list; which endpoint and rule family each challenge maps to is our reading of crAPI's solutions and source (Table 15 shows the mapping). ShopLite's planted list was written by the same team as the rules.
- **Synthetic workload.** Zipf popularity and fixed rates are assumptions; the coverage curve shows how recall depends on volume.
- **Single host.** All services share 127.0.0.1, so traffic cannot attribute a caller by address (a pod IP would in Kubernetes); dependency results rest on traces, workload environment and gateway routes. Latency numbers include CPU contention.
- **Tool tuned on the same testbeds.** Nine fixes above. A system unseen during development would be a stronger test.
- **Same author built tool, miners and ground truth.** The access logs are independent of the tool's code path; the topology files are not independent of the author's understanding.
