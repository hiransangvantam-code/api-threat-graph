# Ten test companies

ShopLite is one system, and the same people wrote it and ATG. To see whether ATG works on
systems built in other ways, this folder has ten more companies, each from a different
industry, with its own mix of language, API gateway, login style, API documents and
deployment habits. Each one is secure by default and has a handful of weaknesses planted on
purpose, written down before any scan in its `ground-truth.json`.

| Company | Industry | Services in | Gateway config read by ATG | Workloads | Endpoints | Planted | Negative controls |
|---|---|---|---|---:|---:|---:|---:|
| [PayNow](paynow/README.md) | Fintech (mobile wallet) | Go | Kong (DB-less, service URLs with a path) | 6 | 11 | 6 | 2 |
| [CareLink](carelink/README.md) | Hospital (patient portal) | Python | nginx (`auth_request`, not traced) | 6 | 12 | 8 | 2 |
| [SkyFly](skyfly/README.md) | Airline | Node.js | Spring Cloud Gateway (`StripPrefix`), partner API keys | 6 | 12 | 7 | 3 |
| [FleetGo](fleetgo/README.md) | Logistics | Go | Istio (own load balancer, STRICT mTLS, ext-authz) | 6 | 11 | 5 | 3 |
| [LearnHub](learnhub/README.md) | Online learning | Node.js | in-house gateway, ConfigMap routes | 7 | 13 | 6 | 2 |
| [StreamBox](streambox/README.md) | Video streaming | Python | Kong (prefix stripping), session cookie | 7 | 12 | 6 | 3 |
| [CityGov](citygov/README.md) | Government e-services | Go | nginx (`${VAR}` upstreams), no TLS | 6 | 10 | 5 | 2 |
| [FoodDash](fooddash/README.md) | Food delivery | Node.js | Istio behind an nginx Ingress, Swagger 2.0 | 7 | 11 | 5 | 2 |
| [InsureCo](insureco/README.md) | Motor insurance | Python | Spring Cloud Gateway (`StripPrefix`) | 6 | 10 | 6 | 2 |
| [TeleMax](telemax/README.md) | Mobile operator | Go | Spring Cloud Gateway (`RewritePath`) | 11 | 18 | 11 | 2 |
| **Total** | | | | **68** | **120** | **65** | **23** |

Workloads count the gateway. Outside APIs (`fx-rates`, `gds-provider`, `bank-switch`) run as
containers too, but are not part of the company's deployment, as in real life.

## Results

| Version | Endpoints found | Planted found (passive-visible) | Findings that are planted | False alarms on controls |
|---|---:|---:|---:|---:|
| v1.3 | 120/120 (precision 75%) | 61/63 | 61/184 (33%) | 6/23 |
| v1.4 | 120/120 | 62/63 | 62/63 (98%) | 0/23 |
| v1.5 | 120/120 | 62/63 | 62/64 (97%) | 0/23 |

Version 1.5 adds no planted find and loses none. Its one extra finding is in FoodDash, whose Istio
Gateway serves plain HTTP on port 8080. That is true but was not planted. Version 1.5 checks Istio
Gateways for TLS; version 1.4 did not. These generated companies are complemented by ten real
open-source systems in `opensource/` (`docs/BENCHMARK_OSS.md`).

## Run one company

Windows: `START-Windows.bat paynow` from the project folder (a Command Prompt or PowerShell
window opened there). macOS and Linux: `sh start.sh paynow`. Any of the ten names works. The
start script starts the company's Docker, starts ATG on that company's network, lets the
company's users send their requests, and runs one scan. The result is at
http://localhost:8080 as usual. `STOP-Windows.bat` / `sh stop.sh` stops everything, the
company too. Plain `START-Windows.bat` still runs ShopLite.

## Run all ten and score them

```
python bench/run_companies.py
```

This runs every company in turn exactly as START does, scores each scan against the
company's `ground-truth.json`, and writes `results/companies/tables-<version>.md` (Tables 25
and 26) plus `review-<version>.md`, which lists every finding that matches no planted
weakness for a person to read. About three minutes per company once the images are built.
It needs Python 3 with PyYAML on the computer that runs Docker.

## What is in a company folder

Only `company.yaml` is written by hand. `python companies/build.py` writes the rest from it
(and `--check` tells you if anything is out of date):

| File | What it is |
|---|---|
| `company.yaml` | The definition: services, routes, gateway, deployment habits, planted weaknesses, negative controls |
| `README.md` | One page about the company and what was planted |
| `docker-compose.yml` | The company's Docker, on its own network `<id>-net` |
| `k8s/` | The company's Kubernetes manifests. ATG reads them; nothing applies them |
| `gateway/` | Gateway config that is not a Kubernetes object (nginx.conf, Spring Cloud Gateway application.yml) |
| `live-specs/` | OpenAPI documents the services publish while running |
| `specs/` | OpenAPI documents kept only as files in the repository |
| `atg-target.yaml` | ATG's Phase 1 configuration for this company (ATG reads it from `/target`) |
| `atg.env` | The network, the gateway address and the folder, for START and the experiment |
| `company.json` | What the services and the traffic generator read while running |
| `ground-truth.json` | Every real endpoint, every planted weakness with its expected rule, every negative control |

## How the companies are built

**Services.** `runtime/` holds one generic service per language. Each container reads
`company.json` and plays one service: its routes, login and role checks, owner checks, calls
to other services and to outside APIs, and errors. The three languages also send their
traces differently, which is part of the test:

| | Python | Node.js | Go |
|---|---|---|---|
| Web framework | Starlette | Express 4 | `net/http` (Go 1.22 route patterns) |
| Tracing | OpenTelemetry SDK, OTLP/HTTP protobuf | OpenTelemetry JS, OTLP/HTTP JSON | small built-in exporter, OTLP/HTTP JSON |
| Span attribute names | current (`http.request.method`, `http.route`) | older (`http.method`, `http.target`, `http.status_code`, `net.peer.name`) | current |

**Gateways.** The gateway process is the same runtime in gateway mode: it routes by path
prefix, rewrites the path, checks the session with the auth service on routes that need one,
and applies rate limits. ATG never talks to it about its configuration. What ATG reads is the
company's real gateway configuration format in `k8s/` or `gateway/` (Kong declarative YAML,
nginx.conf, Spring Cloud Gateway application.yml, Istio VirtualService and policies, or a
ConfigMap route table), and `build.py` writes that configuration and the runtime's routes from
the same definition, so the two always agree.

**Users and data.** Users are `c1`-`c20` (customers), `staff1`-`staff3` and `p1`-`p3`
(partners). The demo login takes only a user name, so nothing in this folder is a password,
key or token: every session is a random value the auth service makes while running. Personal
fields in responses are always `"***"`. Database passwords are referenced from a secret store
(`ExternalSecret`); no value is in the repository.

**The secure baseline.** Unless `company.yaml` says otherwise: pinned image tags, non-root
containers with dropped capabilities, CPU and memory limits, ClusterIP services, a
NetworkPolicy for every workload, TLS on the public entry, a live OpenAPI document for every
service, tracing in every service, authentication on every route except the login, owner
checks on every object, and a rate limit on the login. The planted weaknesses are the
declared exceptions.

**Traffic.** `runtime/python/traffic.py` uses each company the same way: normal use by the
right kind of user, customers asking for other customers' objects, requests without a
credential, customers trying staff and partner functions, failed logins, and the company's
internal jobs. It is seeded, so a run repeats.

## Limits of this test

- The companies are built for the test, by the same team as ATG, so they are not independent
  systems. They do use configuration styles that real teams use and that ATG had not seen
  before (Kong service URLs with a path, `RewritePath`, Istio ext-authz, session cookies), and
  their ground truth was fixed before the first scan.
- The gateway process is not the real Kong, nginx, Spring Cloud Gateway or Envoy. Its
  configuration files are real formats, but nothing checks that the real product would accept
  them.
- Sixteen to twenty rounds of seeded traffic per company is a short observation window.
