# Phases 2-4: data model, scoring and limitations

This is the reference for the paper's Section III (method) and for the professor's three questions: where the rules come from, how the graph nodes are defined, and how mitigation is produced.

## Phase 2: Extended Universal JSON Format (EUJF, `atg.eujf/v1`)

One document per run (`output/eujf.json`):

| Key | Content |
|---|---|
| `services[]` | one per microservice: exposure (`internet / node / internal` + the chain of objects that causes it), NodePort, live/file spec, NetworkPolicy and allowed callers, container flags (privileged, root, mutable tag, limits), plaintext secret env names, Secret refs |
| `endpoints[]` | one per operation, joined across sources on `(service, method, path shape)`. Keeps `sources.spec / traffic / public_traffic / trace` separately (provenance), plus derived facts: `inventory_status`, `public_paths`, `gateway_route`, `auth_observed`, `auth_required`, `data_classes`, `owner_fields`, `returns_collection`, `status_observed` (status codes from both capture points). Bodies and credentials seen only at the gateway still count |
| `gateway_routes[]`, `ingress[]`, `secrets[]` | from manifests |
| `dependencies[]` | service -> service, with evidence `trace`, `config (ENV_NAME)` or `gateway route` |
| `entrypoints[]`, `call_chains[]` | from traces; `from_outside_gateway` marks traces that start at a backend with no traced caller. When the gateway itself emits no spans, an endpoint that receives public traffic is not marked (its caller was most likely the gateway) |

Key joins:

- **Gateway folding.** Gateway traffic `GET /api/users/{int}` is mapped through the route table (prefix `/api/users`, strip `/api`) onto the backend endpoint `GET /users/{user_id}` of user-service. One endpoint, with both its public path and its backend path.
- **Inventory status.** `documented` (spec + observed), `shadow` (observed, no spec), `zombie` (deprecated in spec, still observed), `dormant` (spec only). An endpoint that only ever answered 404/405 has no handler and is ignored.
- **Auth as observed, not as declared.** `auth_required` is `enforced` (anonymous requests got 401/403, none succeeded), `not_enforced` (an anonymous request got 2xx), `declared` (only the spec says so) or `unknown`.

## Phase 3: rule engine

27 deterministic rules in three groups (the three boxes in Fig. 1). Every rule declares:

| Field | Meaning |
|---|---|
| `owasp` | OWASP API Security Top 10 **2023** category |
| `cwe` | MITRE CWE weakness IDs |
| `attack` | MITRE ATT&CK technique IDs |
| `nist` | NIST SP 800-204 (microservices), 800-207 (zero trust), 800-190 (containers), 800-95 (web services), 800-63B (authentication) |
| `likelihood`, `impact` | base values, 1-5 |
| `mitigation`, `snippet` | the fix, with an example |

The full table is the "Rule catalog" section of the dashboard. A rule is a pure function over the EUJF, so the engine has no I/O and runs in about 1 ms for the demo.

### Risk score

`score = L × I`, both clamped to 1-5. Each finding records how it got there, for example:

```
likelihood base 4
impact base 5
likelihood +1: reachable from the internet
=> 5 × 5 = 25 (critical)
```

Adjustments: internet-reachable target +1 likelihood, internal-only −1 (for rules where exposure matters); rule-specific impact +1 for personal data and similar. Severity bands: critical ≥ 20, high ≥ 12, medium ≥ 6, low below 6.

## Threat graph

### Node types

| Type | Definition | ID |
|---|---|---|
| **Actor** | where an attack starts. `internet`: an external attacker who can create an ordinary customer account and nothing more. `in-cluster`: code running in some pod (a compromised container or an unidentified internal job) | `actor:internet`, `actor:in-cluster` |
| **API** | one microservice that serves an API | `svc:<name>` |
| **Endpoint** | one operation (service + method + path) | `ep:<svc>:<METHOD>:<path>` |
| **Dependency** | something of value that an API relies on or hands out: data assets (customer PII, payment records) and credentials (Secrets, plaintext env secrets) | `dep:data:…`, `dep:secret:…`, `dep:env:…` |
| **Vulnerability** | one finding from the rule engine | `vuln:F-001` |
| **Risk** | a business consequence: data breach, financial fraud, account takeover, credential compromise, container/cluster compromise, service disruption, undetected activity, reconnaissance | `risk:<key>` |

### Edge types

| Edge | From → to | Created from |
|---|---|---|
| `reaches` | Actor → API / Endpoint | Ingress, NodePort, missing NetworkPolicy, observed untraced caller |
| `exposes` | API → Endpoint | the service serves it |
| `routes` | gateway API → Endpoint | gateway route (prefix, auth) |
| `calls` | Endpoint → Endpoint | distributed trace call chains |
| `depends_on` | API → API | dependencies (traces, config, routes) |
| `runs_on` | Endpoint → API | lets a path reach service-level weaknesses; after it only `has_vuln` may follow |
| `handles` | Endpoint → Dependency | the endpoint returns that data class |
| `uses` | API → Dependency | the service holds that credential |
| `has_vuln` | Endpoint / API → Vulnerability | finding target |
| `leads_to` | Vulnerability → Risk | the rule's risk category |

The graph is written to the graph store (`atg_nodes`, `atg_edges`), and attack paths are found **inside the database** with a recursive CTE (`graphstore.ATTACK_PATH_SQL`), identical on SQLite and PostgreSQL.

### Attack Path Contextual Risk (APCR)

For each path Actor → … → Vulnerability → Risk:

```
APCR = L × I × entry_factor × 0.95^(chained calls)        range 0-25
entry_factor: internet 1.0, in-cluster 0.5 (a foothold is needed first)
```

Paths are de-duplicated per (actor, first hop, finding). Total attack-path risk R = sum over findings of the best APCR among the paths that reach it.

### Propagated risk

```
propagated(n) = max( own(n), 0.85 × max propagated(child) )     along reaches / exposes / routes / calls
```

A gateway therefore carries the risk of the worst thing it exposes, decayed per hop. This is the number shown on each graph node.

### Mitigation plan

Findings are grouped into remediation actions, because one change often closes several findings (authentication plus a role check on `/admin/transactions` closes TS-01, API5 and API3). Actions are then applied greedily: each step picks the action that removes the most remaining R. Two actions also cut network edges: making a NodePort service ClusterIP removes `actor:internet → service`, and a NetworkPolicy removes `actor:in-cluster → service`. The dashboard lists the order and the cumulative reduction.

## Demo results (ShopLite)

| Scenario | Findings | Critical / high | Attack paths | R |
|---|---|---|---|---|
| vulnerable | 37 | 7 / 20 | 122 | 472 |
| hardened | 2 | 0 / 0 | 2 | 13.5 (−97%) |

The two weaknesses left in the hardened build are there on purpose: a deprecated endpoint still in use, and a cron job that calls an internal endpoint without tracing.

`tests/test_pipeline.py` checks that the 37 findings are exactly the weaknesses built into ShopLite. That is a regression test. The accuracy evaluation (tool vs an oracle threat model built from ground truth, OWASP crAPI's own vulnerability list, measured risk reduction after hardening) is in `docs/EXPERIMENT.md` and `results/tables.md`, Tables 11-20.

## Known limitations (false negatives the rules do not catch)

ShopLite has weaknesses the current rules miss. They are good examples for the paper's limitations section and for new rules:

- `GET /orders?user_id=…` returns any user's orders. API1 only looks at object IDs in the **path**, not in query parameters.
- `POST /orders` trusts `user_id` from the request body, so a customer can create orders for someone else (mass assignment / BOLA through the body).
- The JWT secret is weak (`changeme123`). The extractor never copies secret values, by design, so it cannot judge their strength.
- BOLA detection is heuristic: "object ID in path, authenticated, never saw a 403". An endpoint that returns 404 for other users' objects is safe but still flagged (medium confidence).
- From OWASP crAPI's own list (Table 15): API3 needs the endpoint to be anonymous or shadow, so over-exposure to authenticated users (crAPI #4, #5) is missed; API5 takes a 401 as proof of access control, so a function-level authorization gap for logged-in users (crAPI #7) is reported only through API1; API7 matches field names, so a URL field named `mechanic_api` (crAPI #11) is missed; TS-07 counts 401/403 as failed attempts, while crAPI's OTP check answers 500 (crAPI #3); there is no mass-assignment rule (crAPI #8-10). Injection, token forgery and LLM issues (crAPI #12, #13, #15-18) need payload testing and are out of scope for a passive design review.
- Attack paths only model what the four sources show. No code-level taint analysis (the AST extractor mentioned in the paper text is not in Fig. 1 and not built).
