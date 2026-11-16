# Development history

Work done while ATG was built, before the final evaluation on the ten open-source systems. None of it is part of the report's evaluation (Section V), but all of it still runs.

## Development experiments (ShopLite, Train Ticket, crAPI; earlier draft)

| Where | What |
|---|---|
| `results/tables.md` | Tables 1-10 (Phase 1) and 11-20 (Phases 2-4), mean ± sd over 5 seeds |
| `results/tables/*.csv` | the same tables as CSV |
| `results/stress/tables.md` | Tables 21-22: stress test, system size and call-chain density, version 1.2 vs 1.3 (`bench/stress.py`) |
| `results/zap/tables.md` | Tables 23-24: ATG vs OWASP ZAP 2.16.1 on the same ShopLite build (`bench/compare_zap.py`) |
| `results/figures/*.png` | 10 figures (`fig_stress.png` is the stress test) |
| `results/dashboards/*.html` | Phase 4 output for every testbed and condition |
| `docs/EXPERIMENT.md` | method, oracle, metric definitions, the nine fixes, threats to validity |
| `docs/THREAT_MODEL.md` | node and edge types, scoring, APCR, propagation, rule limitations |
| `docs/LIMITS.md` | what a passive review cannot detect, by OWASP category, and how large a system it handles |
| `docs/COMPARISON_ZAP.md` | the ZAP comparison: setup, results, what it does and does not show |
| `docs/REVIEW_RESPONSES.md` | the seven review points and what changed for each |
| `companies/README.md`, `results/companies/` | ten generated companies in ten industries (Go, Python, Node.js; Kong, nginx, Spring Cloud Gateway, Istio): 120/120 endpoints, 62/63 passive-visible planted weaknesses, 0/23 false alarms |
| `opensource/README.md`, `docs/BENCHMARK_OSS.md` | ten open-source systems (Google, IBM, Spring, Cornell, Istio, ...), ATG v1.4 and v1.5 |
| `results/opensource/comparison.md` | ATG vs Checkov, Kubescape, kube-linter, Polaris, Spectral, Bandit, gosec, njsscan on the ten: accuracy by category, where each tool stops, speed (`bench/compare_tools.py`) |
| `docs/TOOLS_COMPARISON.md` | commercial and research tools (IBM, NVIDIA, Salt, Akamai, Harness, Wiz, Palo Alto, Microsoft, 42Crunch, threat-modelling tools), from their documentation |
| `docs/HARDENING_REPORT.md` | the "What to fix, in order" page every scan writes |

Each run folder keeps its metrics and threat-model output. To keep the repository small, it leaves out the raw captured traffic, traces and ground-truth access logs of the 84 experiment runs (about 420 MB), plus the Phase 1 output of the Train Ticket and crAPI runs. `python bench/report.py` still rebuilds every table and figure from what is here, byte for byte. Rerunning the experiment regenerates the rest.

Reproduce everything (Linux tested; about 45 minutes in total):

```bash
python bench/run_experiment.py grid        # Phase 1, 30 runs
python bench/run_experiment.py hardened    # ShopLite hardened, same seeds
python bench/run_experiment.py overhead --testbed trainticket
python bench/run_experiment.py overhead --testbed crapi
python bench/run_experiment.py scale --testbed trainticket
python bench/run_experiment.py curve --testbed trainticket
python bench/run_threat.py grid            # Phases 2-4 vs oracle
python bench/run_threat.py hardened
python bench/run_threat.py stores          # needs PostgreSQL
python bench/run_threat.py dashboards
python bench/report.py
```

`realcheck/` is a kit to repeat the Phase 1 measurement on the real crAPI running in Docker on your own machine (Thai guide inside). It has not been run yet.

## ShopLite by hand (two Dockers)

| Compose project | Containers | Role |
|---|---|---|
| `target/docker-compose.yml` (`shoplite`) | api-gateway, user-service, order-service, payment-service; `users` on demand | the company's system; two settings point it at ATG for the review: `MESH_PROXY` and `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `docker-compose.yml` (`atg`) | atg-proxy (mitmproxy), atg-collector (OpenTelemetry Collector 0.111.0), atg-postgres (PostgreSQL 16), atg (scanner + web) | our platform, attached to `customer-net` |

By hand: start the target (`docker compose -f target/docker-compose.yml up -d --build --wait`), then ATG (`docker compose up -d --build`), send customers (`docker compose -f target/docker-compose.yml run --rm users`) and scan (`docker compose exec atg python docker/scan.py --label vulnerable`). Each scan reads only what the sidecar and the Collector wrote since the previous scan, then clears it from their in-memory buffers. The report pages and exports are written to `output/site/`; the per-phase files stay in memory under http://localhost:8080/live/ until STOP. Guide: `HOW-TO-RUN.md`.

Tested end to end with `sh start.sh` from a clean copy: 407 HTTP flows through the sidecar and 32 span batches through the Collector in the first scan, giving the same findings and attack-path risk as the local demo. That test machine could not reach Docker Hub, so it used locally built stand-ins. For `python:3.12-slim` it used Python 3.12 on Ubuntu 24.04, and for `postgres:16-alpine` PostgreSQL 16 with UTF-8 and the same environment variables. For `otel/opentelemetry-collector-contrib:0.111.0` it used the official 0.111.0 binary from GitHub. A normal machine pulls the official images.

## The professor's review: ten open-source systems and other tools (version 1.5)

The professor's review asked for real open-source systems in different fields, a comparison with other
tools, and recommendations instead of percentages. `opensource/` holds ten systems at pinned commits:
Online Boutique, Bank of Anthos, Stan's Robot Shop, Acme Air, Spring PetClinic, PiggyMetrics, Lakeside
Mutual, FTGO, Hotel Reservation and Bookinfo. ATG and eight free tools ran on all ten against the same
712 labelled weaknesses (`docs/BENCHMARK_OSS.md`):

| | ATG v1.6 | best Kubernetes scanner (Polaris) | ATG + Checkov |
|---|---:|---:|---:|
| Systems it can run on | 10/10 | 7/10 (no Docker Compose) | 10/10 |
| Labels found | 462/712 (65%) | 349/712 (49%) | 611/712 (86%) |
| API behaviour, inventory | 52/82, 84/84 | 0, 0 | 52/82, 84/84 |
| Deployment configuration | 326/546 (60%) | 349/546 (64%) | |
| Precision | 75% | 95% | |

The code scanners (Bandit, gosec, njsscan) each read one language, 26 of the 65 services together.
To rerun the whole comparison on your own computer: `DEMO-ALL-Windows.bat`, then `BENCH-Windows.bat`
(or `sh demo-all.sh`, then `sh bench.sh`). BENCH runs the eight tools in one Docker image, scores
everything against the same labels and opens `results/opensource/comparison.html` with all the charts
and tables (`bench/oss_figures.py`).
`sh start.sh bookinfo` (or `START-Windows.bat bookinfo`) reviews one of them with stand-in services, and
`sh real.sh robot-shop` (or `REAL-Windows.bat robot-shop`) runs seven of them on their real images
(`opensource/real/README.md`). Version 1.5 fixed gaps that v1.4 showed on these systems, so read its
numbers with the caveat in `docs/BENCHMARK_OSS.md`; v1.4 found 333/712 (47%).
