# Phase 1 design notes

## The idea in one paragraph

No single source shows the whole API. A spec shows what the team meant to build. Traffic shows what is actually called, including things nobody documented. Manifests show what is deployed and how reachable it is. Traces show who calls whom. Phase 1 collects all four separately and faithfully, and does not decide anything yet. Merging is Phase 2, judging is Phase 3.

## What each source can and cannot see in ShopLite

| | mitmproxy | OpenAPI | K8s manifests | OpenTelemetry |
|---|---|---|---|---|
| `GET /internal/users/export` (hidden, no auth) | yes | no (`include_in_schema=False`) | no | yes, as a trace that starts inside the cluster |
| payment-service (`openapi_url=None`) | yes | only a stale file listing `/charge` | yes, NodePort 30083, privileged | yes |
| `/api/payments/**` route without auth | yes, requests without token | no | yes, gateway ConfigMap `auth: none` | yes |
| order -> user, order -> payment calls | yes (east-west) | no | partly, URLs in env vars | yes, with counts and latency |
| `JWT_SECRET` in plaintext | no | no | yes (name only, value never copied) | no |
| emails and phone numbers in responses | yes (as `string:email`, `string:phone`) | no | no | no |

That table is the argument for using four sources, and the report shows it with the real run.

## Decisions worth knowing

1. **Privacy at capture time.** The mitmproxy addon turns bodies into shapes and drops auth values before anything is written. A captured file can be shared or committed without leaking customer data. This supports the paper's on-premise, zero-exfiltration claim with something checkable (`tests/test_extractors.py` greps the output for the demo's secrets).
2. **Two capture points.** Reverse proxy in front of the gateway for north-south, forward proxy that services use for east-west. In a real cluster the east-west point would be a sidecar or the service mesh; the addon does not care which.
3. **The demo gateway reads its routes from the same ConfigMap the extractor parses**, so the "gateway discovery" output cannot drift from real behaviour.
4. **The extractor filters its own noise.** OpenAPI probes carry `User-Agent: atg-extractor/...`, and traces started by them (and health checks) are dropped. Without this, every probe showed up as a fake entry point.
5. **One envelope for every file**, with a manifest and hashes, so Phase 2 can be built in parallel against the contract.
6. **Facts, not findings.** The extractor records `privileged: true` or `auth: none`; it never says "vulnerable". Rules belong to the rule engine.

## Deliberate weak spots in ShopLite (for Phase 3 to find later)

- Shadow endpoint `/internal/users/export`, no auth, returns all users with email and phone
- `/api/payments/**` exposed through the gateway without auth, reaching `/admin/transactions`
- `GET /orders/{order_id}` has no ownership check (BOLA); the traffic generator reads other users' orders
- payment-service: no spec, NodePort, privileged, runs as root, `:latest` tag, API key in plaintext env
- order-service: `JWT_SECRET` in plaintext env, no resource limits
- Gateway `/_debug/config` leaks the routing table; Ingress has no TLS
- Only user-service has a NetworkPolicy
- A deprecated operation (`DELETE /orders/{order_id}`) still in use

## Not in Phase 1 yet

- Source-code AST extraction (mentioned in the paper text but not in Fig. 1)
- gRPC: traces handle `rpc.*` attributes, but there is no protobuf/reflection discovery
- Helm charts (render them with `helm template` first, then feed the YAML)
- Real cluster access (reads manifests from disk, not the live API server)

## Suggested Phase 2 starting point

1. Build the service list as the union of: K8s workloads, OTel `service.name`, `service_map` values.
2. Join endpoints from spec, traffic and trace on `(service, match_key(method, path))`.
3. Keep provenance on every merged field (`seen_in: ["traffic", "trace"]`), since Phase 3 rules will need to know *who* says what.
4. Attach infra facts (exposure, network policy, env) to the service node, and gateway routes as edges from the gateway to the upstream service.
