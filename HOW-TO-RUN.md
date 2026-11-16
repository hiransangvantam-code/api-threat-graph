# How to run API Threat Graph (two Dockers)

The setup has two Docker deployments, as in Fig. 1 of the paper.

| Docker | What it is | File |
|---|---|---|
| Company Docker (target) | The system under review: ShopLite, four microservices (api-gateway, user-service, order-service, payment-service) on the network `customer-net` | `target/docker-compose.yml` |
| ATG Docker (ours) | Joins the company's network, collects the four Phase 1 sources and runs Phases 1-4 | `docker-compose.yml` |

The ATG Docker has four containers:

| Container | What it does | Phase |
|---|---|---|
| `atg-proxy` | mitmproxy as a sidecar in front of the gateway. Customers come in through it, and the company's services call each other through it. | 1 (runtime traffic) |
| `atg-collector` | OpenTelemetry Collector. Receives the spans the company's services send. | 1 (traces) |
| `atg-postgres` | PostgreSQL with the EUJF records (`atg_eujf`) and the threat graph (`atg_nodes`, `atg_edges`, ...). Runs in memory. | 2, 3 |
| `atg` | Reads the services' OpenAPI documents and the company's manifests, runs Phases 1-4, and serves the pages at http://localhost:8080 | 1-4 |

Nothing leaves the company network, and nothing from the company is kept on your computer after STOP except the report pages and the exported threat graph (see `docs/DATA_HANDLING.md`).

## What you need

1. Docker Desktop (https://www.docker.com/products/docker-desktop/), open and showing "Engine running". On Windows, accept the WSL 2 prompt if it appears; it may need one restart.
2. Internet access the first time. Docker downloads a few hundred MB and builds the images, which takes 5-10 minutes. Later starts take about 2 minutes.

## Start

Windows: open the project folder, click the address bar, type `powershell`, press Enter, then run `.\START-Windows.bat`. Double-clicking the file works too. If Windows shows "Windows protected your PC", click More info, then Run anyway.

macOS / Linux: open a terminal in the folder and run `sh start.sh`.

The script runs six steps and prints which one it is on:

1. Starts the company Docker (ShopLite as shipped, with its weaknesses).
2. Starts the ATG Docker and opens http://localhost:8080. Until the first scan, that page shows whether every container of both Dockers is up.
3. Simulated customers use the shop. Their traffic goes through ATG's sidecar.
4. Scan 1 (Phases 1-4). The page switches to the threat graph.
5. The company deploys the fixed version, and the customers use the shop again.
6. Scan 2. The home page shows the before/after comparison (attack-path risk 472 → 13.5).

When the window says `Done`, press F5 in the browser.

Every start is a fresh review. The pages and exports of the previous review are replaced, so copy `output\site` somewhere first if you want to keep them.

## What the pages show

| Page | Content | Kept after STOP |
|---|---|---|
| Home (`index.html`) | Threat graph preview, before/after table, the four phases, all scans, export links, what was kept and deleted, the two-Docker diagram, the Section IV results | yes |
| `threat-graph.html` | The threat graph, full screen. Click a node or an attack path. Download buttons for the four export formats at the top. | yes |
| `dashboard-1-vulnerable.html` | The full Phase 4 dashboard: API overview (by source and by confidence HIGH/MEDIUM/ZOMBIE), risk summary, top vulnerabilities, attack paths, fix plan | yes |
| `hardening-1-vulnerable.html` | What to fix, in order: the risk after each fix, every finding with why it matters, the fix for this system's own gateway / Kubernetes / framework, how to check the fix, a hardening baseline per service, accuracy and speed (`docs/HARDENING_REPORT.md`). Also as `exports/1-vulnerable/hardening.md` | yes |
| `exports/1-vulnerable/` | The threat graph as GraphML, JSON, SARIF and SVG (`docs/EXPORT_FORMATS.md`) | yes |
| `live/phase1-report-1-vulnerable.html` | What each Phase 1 source found | no, only while running |
| `live/scans/1-vulnerable/eujf.json` | The Phase 2 output as EUJF records (Algorithm 1 in the paper) | no, only while running |
| `live/scans/1-vulnerable/raw/*.json` | Raw Phase 1 output, one file per source | no, only while running |

The `live/` pages are kept in memory, so they work only while the review is running.

## Export the threat graph

Each scan saves its graph to `output\site\exports\<scan>\`:

- `threat-graph.graphml` to open the graph in Gephi, yEd, Cytoscape, Neo4j or NetworkX
- `findings.sarif` to put the findings into a vulnerability tracker or a CI pipeline
- `threat-graph.json` for scripts (it also has the attack paths and the fix plan)
- `threat-graph.svg` for a report or the paper

`docs/EXPORT_FORMATS.md` explains the choice of formats.

## Stop, and clean up

| | Windows | macOS / Linux | What is deleted | What stays |
|---|---|---|---|---|
| STOP | `STOP-Windows.bat` | `sh stop.sh` | Both Dockers, the captured traffic and spans, Phase 1 files, EUJF/analysis JSON, the database | `output\site`: report pages and exports |
| CLEAN | `CLEAN-Windows.bat` | `sh clean.sh` | Everything STOP deletes, plus `output\` | nothing |

Run STOP when you finish a demo or a review. Run CLEAN after the report has been handed over. CLEAN asks you to type YES first.

Closing the PowerShell window does not stop Docker. Use STOP.

## Run it one step at a time (to walk someone through the phases)

```sh
docker compose -f target/docker-compose.yml up -d --build --wait     # 1. company Docker
docker compose up -d --build                                           # 2. ATG Docker -> http://localhost:8080
docker compose -f target/docker-compose.yml run --rm users             # 3. customers use the shop (through the sidecar)
docker compose exec atg python docker/scan.py --label vulnerable       # 4. Phases 1-4
```

To deploy the fixed version (PowerShell: `$env:SHOPLITE_HARDENED="1"; $env:SHOPLITE_MANIFESTS="k8s-hardened"` instead of the first line):

```sh
export SHOPLITE_HARDENED=1 SHOPLITE_MANIFESTS=k8s-hardened
docker compose -f target/docker-compose.yml up -d --wait
docker compose -f target/docker-compose.yml run --rm users
docker compose exec atg python docker/scan.py --label hardened --manifests k8s-hardened
```

Finish with `docker compose down -v` and `docker compose -f target/docker-compose.yml --profile users down -v` (that is what STOP does).

## Look inside PostgreSQL

While it runs:

```sh
docker compose exec atg-postgres psql -U atg -c "SELECT api_id, method, endpoint, auth, confidence FROM atg_eujf;"
docker compose exec atg-postgres psql -U atg -c "SELECT rel, COUNT(*) FROM atg_edges GROUP BY rel;"
```

The first shows the Phase 2 EUJF records. The second shows the threat graph's edges, named as in eq. (3) of the paper (ROUTES_TO, CALLS, QUERIES, HAS_FINDING, ...).

## The test systems: ten generated companies and ten open-source systems

Besides ShopLite, START can review the twenty test systems. Each one runs in its own company Docker, and
ATG joins its network:

```powershell
START-Windows.bat paynow          # one of the ten generated companies (companies\README.md)
START-Windows.bat bookinfo        # one of the ten open-source systems, with stand-in services (opensource\README.md)
```

```bash
sh start.sh paynow
sh start.sh bookinfo
```

The open-source names are `online-boutique`, `bank-of-anthos`, `robot-shop`, `acme-air`, `petclinic`,
`piggymetrics`, `lakeside-mutual`, `ftgo`, `hotel-reservation` and `bookinfo`. The first start of one
downloads its code at the pinned commit, because ATG reads its real deployment files.

To review seven of them on their **real images** instead (needs internet; the first run downloads a few GB):

```powershell
REAL-Windows.bat robot-shop       # or: petclinic lakeside-mutual hotel-reservation piggymetrics bookinfo online-boutique
```

```bash
sh real.sh robot-shop
```

ATG is then on http://localhost:18080, and the result goes to `results\opensource\atg-real\`. Details:
`opensource\real\README.md`.

## Rerun the comparison with eight other tools (the evaluation charts)

Two scripts rerun the whole open-source benchmark on your computer and draw every chart and table from
what they measure. Only Docker and internet are needed.

```powershell
DEMO-ALL-Windows.bat       # 1. ATG reviews the ten systems (about 10 minutes); saves results\opensource\atg-laptop\
BENCH-Windows.bat          # 2. eight other tools on the same ten systems, scoring, charts (first time 5-10 minutes)
```

```bash
sh demo-all.sh
sh bench.sh
```

BENCH builds one Docker image with Checkov, Kubescape, kube-linter, Polaris, Spectral (OWASP ruleset),
Bandit, gosec and njsscan, runs each of them on the ten systems' files, scores them and ATG against the
same 716 labels, and opens `results\opensource\comparison.html`: five charts (found by category, per
system, where each tool stops, speed, the fix plans) and every table. The charts are also saved as PNG
files in `results\opensource\figures\`, and the tables in `results\opensource\comparison.md`.

## Review another system (not ShopLite)

The company changes two settings in its own deployment for the duration of the review:

1. Its services send their east-west calls through the sidecar, for example with `HTTP_PROXY=http://atg-proxy:8081` for HTTP clients that read that variable (ShopLite reads `MESH_PROXY`). Its public traffic goes to `atg-proxy:8080` instead of straight to the gateway, for example by pointing the ingress or load balancer there.
2. Its services export spans with OpenTelemetry to `http://atg-collector:4318`.

On the ATG side:

1. Put the company's manifests, gateway configuration and any OpenAPI files in one folder, for example `D:\review\acme\k8s\` and `D:\review\acme\specs\`.
2. Edit `docker/extractor-target.yaml`: the target name, `service_map` (host:port on the wire to service name), `live_targets` (each service's base URL inside the network) and `spec_files`.
3. Start ATG with the company's settings:

   ```powershell
   $env:TARGET_NETWORK="acme-net"                       # the company's Docker network
   $env:TARGET_GATEWAY="http://acme-gateway:8080"       # where the sidecar forwards public traffic
   $env:TARGET_CONFIG="D:\review\acme"                  # mounted read-only at /target
   docker compose up -d --build
   ```

4. Let real or test traffic run for a while, then scan: `docker compose exec atg python docker/scan.py --label first --manifests k8s`
5. Hand over `output\site` (or just the exports), then run STOP and CLEAN.

Scan as often as you like. Each scan reads only what arrived since the previous one and clears it from memory.

## Common problems

| Problem | Fix |
|---|---|
| `Docker Desktop is not running` | Open Docker Desktop, wait for "Engine running", try again |
| `network customer-net ... not found` | The company Docker has to start first (step 1). START does this for you. |
| Port 8080 is in use | Close the program using it, or on macOS/Linux run `ATG_PORT=9090 sh start.sh` and open http://localhost:9090. `START-Windows.bat` always uses 8080. |
| The page says "The scan stopped with an error" | The page shows the log. Run STOP, then START. If it fails again, send the log. |
| The first start is slow | Expected. Docker downloads Python, PostgreSQL, the OpenTelemetry Collector and the libraries once. |
| A `live/` link says 404 | The review is no longer running, so that in-memory data is gone. This is on purpose. |

## Where each phase is in the code

`docs/PAPER_MAPPING.md` maps the paper to the code.

| Folder / file | What it is |
|---|---|
| `target/` | Company Docker (compose file and Dockerfile) |
| `demo_target/` | ShopLite's code, manifests (`k8s`, `k8s-hardened`) and spec file |
| `docker-compose.yml`, `Dockerfile` | ATG Docker |
| `docker/scan.py` | One scan: Phases 1-4 on what arrived since the previous scan, then the clean-up and the exports |
| `docker/serve.py`, `docker/pages.py` | The pages on port 8080 |
| `docker/otel-collector.yaml` | OpenTelemetry Collector settings |
| `docker/extractor-target.yaml` | Service names and URLs of the system under review |
| `extractor/` | Phase 1 |
| `atg/normalizer.py` | Phase 2 (EUJF) |
| `atg/rules.py`, `atg/analysis.py`, `atg/graphstore.py` | Phase 3 |
| `atg/dashboard.py`, `atg/export.py` | Phase 4 (pages and exports) |
| `bench/`, `results/` | The Section IV experiments and their results, the stress test and the ZAP comparison |
