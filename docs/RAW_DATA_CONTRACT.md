# Raw API data contract (`atg.raw/v1`)

This is the interface between Phase 1 (Extractor) and Phase 2 (API Normalizer). If you build the normalizer, this file is all you need to read. If you change an extractor, keep this file in sync.

## Envelope (every file)

```json
{
  "schema": "atg.raw/v1",
  "source": "runtime_traffic | openapi | infrastructure | callchain",
  "collector": "mitmproxy | openapi-prober | k8s-manifest-parser | opentelemetry",
  "extractor_version": "0.1.0",
  "run_id": "20261002-003212-350e28",
  "collected_at": "2026-10-01T17:32:12+00:00",
  "duration_ms": 10.3,
  "inputs": ["output/capture/flows.jsonl"],
  "stats": { "...": "source specific counters" },
  "warnings": ["human readable, never fatal"],
  "records": [ { "kind": "...", "...": "..." } ]
}
```

`manifest.json` lists every source file with its status, record count and SHA-256, so a later phase can tell which run it is reading.

Rules that hold for all sources:

- Every record has a `kind`.
- Services are always referred to by name (from `target.service_map`, the OTel `service.name`, or the K8s object name). The normalizer joins on this.
- No secret or personal values are stored. Bodies become *shapes*: `{"email": "string:email", "id": "integer"}`. Possible string formats: `email, phone, card_number, jwt, uuid, datetime, url, ipv4`. Several observed types are joined with `|`.
- Paths from traffic are templated: `{int}`, `{uuid}`, `{hex}`, `{id}`. Specs and traces keep their own names (`{user_id}`). To compare, replace every `{...}` with `{}` (`extractor.common.match_key`).

## runtime_traffic.json

| kind | meaning |
|---|---|
| `endpoint` | one service + method + path template, aggregated over every request seen |

```json
{
  "kind": "endpoint", "service": "user-service", "method": "GET",
  "path_template": "/users/{int}", "path_params": [{"position": 2, "kind": "int"}],
  "query_params": [], "hosts": ["127.0.0.1:8001"], "capture_points": ["east-west"],
  "hits": 44, "status_codes": {"200": 44}, "transport_errors": 0,
  "auth": {"authorization_header_seen": 44, "authorization_header_missing": 0,
           "schemes": ["Bearer"], "cookie_names": []},
  "request":  {"content_types": [], "body_shape": null},
  "response": {"content_types": ["application/json"],
               "body_shape": {"id": "integer", "email": "string:email", "phone": "string:phone"}},
  "latency_ms": {"p50": 6.1, "max": 14.0},
  "example_paths": ["/users/17"], "first_seen": 1790875875.4, "last_seen": 1790875879.9
}
```

`capture_points`: `north-south` (through the reverse proxy in front of the edge), `east-west` (service to service), `har`.

## openapi.json

| kind | meaning |
|---|---|
| `spec` | one OpenAPI/Swagger document, live or from a file, with `operations[]` flattened |

Extra top-level key: `probe_log` (every URL tried and its result).

```json
{
  "kind": "spec", "service": "payment-service", "origin": "file",
  "location": "demo_target/specs/payment-service.v1.yaml", "spec_version": "3.0.3",
  "title": "payment-service", "api_version": "0.7.0", "servers": ["http://payment-service:8003"],
  "security_schemes": {"serviceToken": {"type": "apiKey", "in": "header", "name": "X-Service-Token"}},
  "global_security": null, "operation_count": 1,
  "operations": [{
    "method": "POST", "path": "/charge", "operation_id": "charge", "summary": "...", "tags": [],
    "deprecated": false,
    "parameters": [{"name": "...", "in": "path|query|header|cookie", "required": true, "type": "integer"}],
    "request_body": {"required": true, "content_types": ["application/json"],
                     "fields": {"user_id": "integer", "amount": "number", "card_token": "string"}},
    "responses": ["200"], "security": [{"serviceToken": []}],
    "auth_declared": "required | optional | none"
  }]
}
```

Optional request-body fields end with `?` (`"nickname": "string?"`).

One document published for the whole API at the gateway (crAPI does this) can be split per backend with `service_by_prefix` in `extractor.yaml`; it then yields one `spec` record per backend service, all with the same `location`.

## infrastructure.json

| kind | meaning |
|---|---|
| `workload` | Deployment / StatefulSet / DaemonSet / Job / CronJob / Pod, with `containers[]` |
| `service` | K8s Service, `type`, `ports`, `selects_workloads` |
| `ingress` | one host + path rule, `backend_service`, `tls` |
| `gateway_route` | `match_prefix` -> `upstream_service`, `strip_prefix`, `auth` (`required/none/unspecified`), `gateway` (`configmap/istio/kong/spring-cloud-gateway/nginx`). Routes read from a gateway's own config file (`gateway_configs` in extractor.yaml) also carry `gateway_service` (the workload that is the gateway) and `pattern` (the original route pattern) |
| `network_policy` | `pod_selector`, `ingress_from` |
| `secret` | name and key names only |
| `configmap` | name, keys, `is_gateway_config` |
| `exposure` | computed: `workload`, `level` (`internet / node / internal`), `via` (the chain of objects that makes it reachable) |

Container env entries: `{"name", "source": "plaintext|secretRef|configMapRef|fieldRef", "sensitive_name": bool}` plus `value` only for URLs and host:port values (dependency hints, with `references_service` when the host is a known Service). Other plaintext values become `value_length`.

## callchain.json

| kind | meaning |
|---|---|
| `service` | service name, span count, `served_operations[]` |
| `edge` | `from` -> `to`, `calls`, `operations[]` (`count`, `errors`, `p50_ms`), `evidence` |
| `entrypoint` | operation where a trace starts (nobody traced called it) |
| `call_chain` | distinct end-to-end path, `hops[]` with `depth`, `service`, `operation`; `traces` = how many times seen |

Traces caused by the extractor itself (User-Agent `atg-extractor/*`) and health checks (`ignore_paths`) are dropped and counted in `stats.spans_ignored`.
