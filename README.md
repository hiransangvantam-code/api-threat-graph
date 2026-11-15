# API Threat Graph

Automatic API security design review for microservices using threat graph analysis. This repository holds a working prototype of all four phases of the architecture (Fig. 1 of the paper) and the experiment behind Section IV, which measures every phase against ground truth on three microservice systems.

![Threat graph page: columns from attacker to impact, attack paths ranked by APCR on the right](docs/images/threat-graph.png)

## Run it

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/), started and showing "Engine running".

```bash
git clone https://github.com/hiransangvantam-code/api-threat-graph.git
cd api-threat-graph
docker compose up --build        # then open http://localhost:8080
```

- **Windows:** run `START-Windows.bat`; stop with `STOP-Windows.bat`; delete everything with `CLEAN-Windows.bat`
- **macOS / Linux:** `sh start.sh`; stop with `sh stop.sh`; delete everything with `sh clean.sh`
- **Step-by-step guide:** [HOW-TO-RUN.md](HOW-TO-RUN.md), including how to review a system other than ShopLite

Two Docker deployments start, as in Fig. 1 of the paper:

- **the company's Docker** (`target/docker-compose.yml`): ShopLite, a demo shop of four microservices, on its own network `customer-net`
- **the ATG platform** (`docker-compose.yml`): joins `customer-net` and collects all four Phase 1 sources from it. A mitmproxy sidecar sits inline in front of the gateway and carries the services' east-west calls. An OpenTelemetry Collector receives their spans. ATG also probes their OpenAPI documents and reads the company's manifests, mounted read-only. EUJF records and the threat graph go to PostgreSQL.

![The company's Docker and the ATG Docker: traffic through the sidecar, spans to the Collector, OpenAPI probe, manifests read-only, Phases 1-4, PostgreSQL](docs/images/two-dockers.png)

The start script runs two scans, one on ShopLite as shipped and one after the company deploys the fixes. The first build takes a few minutes; the scans take about two more. The home page at http://localhost:8080 then shows the threat graph and the before/after numbers: attack-path risk drops from 472 to 13.5. [docs/PAPER_MAPPING.md](docs/PAPER_MAPPING.md) maps every part of Section III to the code.

![Home page with a preview of the threat graph and the before/after table](docs/images/home.png)

## What is kept after a review

The system under review belongs to another company, so ATG keeps as little of it as it can ([docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)):

- Captured traffic and spans are held in memory only (tmpfs volumes), never on disk. Each scan clears what it has read.
- Phase 1 files, EUJF and analysis JSON and the PostgreSQL database are in memory too. STOP deletes all of it.
- Only the report pages and the threat graph exports are written to disk (`output/site/`). CLEAN deletes those once they have been handed over.

## Exporting the threat graph

Each scan writes its graph to `output/site/exports/<scan>/` as GraphML (for Gephi, yEd, Cytoscape, Neo4j, NetworkX), node-link JSON (for scripts; includes attack paths and the fix plan), SARIF 2.1.0 (the findings, for trackers and CI) and SVG (for reports). Why these formats: [docs/EXPORT_FORMATS.md](docs/EXPORT_FORMATS.md).

## How it works

```
1 EXTRACTOR        mitmproxy · OpenAPI · K8s manifests · OpenTelemetry  -> output/raw/*.json      (+ output/report.html)
2 API NORMALIZER   merge into the Extended Universal JSON Format (EUJF)   -> output/eujf.json
                   + API inventory (documented / shadow / zombie / dormant)
3 ANALYSIS & RISK  dependency analyzer · rule engine (27 rules) ·         -> output/analysis.json
                   vulnerability analyzer · threat graph in a graph store  -> output/atg.db or PostgreSQL
                   (SQLite or PostgreSQL) · attack path analysis (SQL)
4 OUTPUT           dashboard: API overview · risk summary · top            -> output/dashboard.html
                   vulnerabilities · trend & insight · fix plan
                   what to fix, in order: risk after each fix, the fix   -> hardening-<scan>.html, hardening.md
                   in the system's own stack, how to verify, baseline
```

## สรุปภาษาไทย

แพ็กนี้มีสองส่วน คือตัวระบบที่รันได้ครบ 4 phase และชุดทดลองที่วัดผลทุก phase เทียบกับ ground truth ผลทั้งหมดอยู่ใน `results/tables.md` (20 ตาราง) และ `results/figures/` (9 รูป) วิธีทดลองกับข้อจำกัดอยู่ใน `docs/EXPERIMENT.md`

### โชว์เพื่อนยังไง

1. **ด้วย Docker (ง่ายสุด):** Windows ดับเบิลคลิก `START-Windows.bat` ส่วน Mac/Linux พิมพ์ `sh start.sh` สคริปต์จะเปิด Docker 2 ชุด คือ Docker ของบริษัท (ShopLite) กับ Docker ของ ATG ที่เข้าไปต่อกับ network ของบริษัท จากนั้น scan ก่อนและหลังแก้ แล้วเปิด http://localhost:8080 ให้ วิธีละเอียดอยู่ใน `HOW-TO-RUN.md` และตารางเทียบ paper กับโค้ดอยู่ใน `docs/PAPER_MAPPING.md`
2. **ไม่มี Docker และไม่อยากรันอะไร:** เปิด `results/dashboards/crapi-C2.html` หรือ `results/dashboards/trainticket-C2.html` ในเบราว์เซอร์ได้เลย เป็น dashboard ของ Phase 4 บน API ของ crAPI (OWASP) และ Train Ticket ที่สร้างตามซอร์สโค้ดจริง
3. **ไม่มี Docker แต่มี Python:** ทำตาม Quick start ด้านล่าง ใช้เวลาราว 30 วินาที

### ผลการทดลองโดยย่อ

ทดลองกับ 3 ระบบ: ShopLite (12 endpoints), Train Ticket (272 endpoints, 45 services) และ crAPI (79 endpoints) อย่างละ 2 เงื่อนไข × 5 seeds C1 คือดักได้ทุกอย่าง ส่วน C2 คือดักได้แค่ขาเข้าและ 30% ของ service ไม่มี trace ซึ่งใกล้ของจริงกว่า ตัวเลขด้านล่างเป็นของ C2

| | ShopLite | Train Ticket | crAPI |
|---|---|---|---|
| Phase 1: recall รวม 4 แหล่ง (endpoint ที่สังเกตได้) | 0.965 | 0.998 | 0.972 |
| Phase 1: precision ของ inventory | 1.000 | 1.000 | 1.000 |
| Phase 1: แหล่งเดียวที่ดีที่สุด (recall) | 0.830 | 0.963 | 0.838 |
| Phase 3: F1 ของ findings เทียบ oracle | 0.90 | 0.93 | 0.97 |
| Phase 3: recall ของ attack paths เทียบ oracle | 0.86 | 0.87 | 0.93 |
| Phase 3: risk ที่วัดได้ / risk จริง | 0.85 | 0.85 | 0.96 |
| เวลาทั้ง 4 phase ต่อรอบ (SQLite) | 0.3 s | 13-17 s | 1.1 s |

สิ่งที่ผลบอก:

- ไม่มีแหล่งข้อมูลไหนชนะทุกระบบ การรวม 4 แหล่งได้ทั้ง inventory ที่ครบกว่าและ threat model ที่ใกล้ความจริงกว่า ถ้าใช้แหล่งเดียว F1 ของ findings ไม่เกิน 0.40 ถ้ารวมครบ 4 แหล่งได้ 0.90-0.97
- **Oracle** คือ threat model ที่ได้จาก ground truth ล้วน ๆ (เหมือนรู้ทุกอย่างของระบบ) แล้วใช้ rule ชุดเดียวกัน ภายใต้ C1 ผลของเครื่องมือตรงกับ oracle ทุกตัว ภายใต้ C2 สิ่งที่หายไปคือสิ่งที่มองไม่เห็นจริง ๆ เช่น TS-08 ที่ต้องเห็น traffic ระหว่าง service
- **การแก้ระบบตามแผนช่วยได้จริง:** ShopLite หลังแก้ตามคำแนะนำของ dashboard ความเสี่ยงของ attack path ลดลง 97.1% (C1) และ attack path เหลือ 2 จาก 121
- **ตรวจกับรายการช่องโหว่ของ OWASP เอง (crAPI 18 ข้อ):** ข้อที่การวิเคราะห์ระดับ design แบบไม่ยิง payload มองเห็นได้มี 12 ข้อ เครื่องมือชี้ endpoint ที่มีปัญหาได้ 4 ข้อในทุกรอบ (ข้อ 7-10 ในฐานะ BOLA) และข้อ 14 อีกข้อใน 1 จาก 5 seeds ซึ่งเป็นข้อเดียวที่ตรงหมวด ข้อที่พลาดไม่ได้เกิดจากการเก็บข้อมูล (oracle ก็พลาดเหมือนกัน) แต่มาจาก rule ที่ยังไม่รองรับ จาก replica ที่ไม่มีเนื้อหา response จริง (ข้อ 1, 4, 5) และจาก workload (ข้อ 14) รายละเอียดอยู่ในตาราง 15
- ระหว่างทดลองเจอ bug ของเครื่องมือ 9 ตัว แก้ไปแล้วทั้งหมด (ตาราง 20 แสดงผลก่อนและหลังแก้) ต้องเขียนเรื่องนี้ในรายงาน

## Run without Docker (Python)

```bash
python -m venv venv
# Windows PowerShell:  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass ; .\venv\Scripts\Activate.ps1
# macOS / Linux:       source venv/bin/activate
pip install -r requirements.txt

python scripts/run_demo.py --scenario both      # all four phases, about 30 s
# open output/dashboard.html                    (Windows: start output\dashboard.html)
python -m pytest -q
```

| Command | What you get |
|---|---|
| `python scripts/run_extractor.py` | Phase 1 only: `output/raw/*.json` + `output/report.html` |
| `python scripts/run_demo.py` | Phases 1-4 on vulnerable ShopLite |
| `python scripts/run_demo.py --scenario hardened` | ShopLite after the recommended fixes |
| `python scripts/run_demo.py --scenario both` | both; the trend chart shows before and after |
| `python -m atg --config extractor.yaml --skip-extract` | re-run Phases 2-4 on the last extraction |

`output/dashboard.html` is always the latest run; `--scenario both` also writes `output/dashboard-vulnerable.html` and `output/dashboard-hardened.html`. Every run is kept in `output/runs/<run_id>/`.

## Results (Section IV)

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

## PostgreSQL instead of SQLite

The threat graph goes into SQLite (`output/atg.db`) by default. The same tables and the same recursive attack path query run on PostgreSQL, which answered the attack path query about 30 times faster on crAPI and 120 times faster on Train Ticket (Table 19):

```bash
pip install -r requirements-postgres.txt
# PowerShell: $env:ATG_GRAPH_STORE="postgresql://atg:atg@localhost:5432/atg"
export ATG_GRAPH_STORE=postgresql://atg:atg@localhost:5432/atg
python scripts/run_demo.py
```

A test checks that both backends return identical attack paths (`ATG_TEST_PG=postgresql://... python -m pytest`).

## Docker details

| Compose project | Containers | Role |
|---|---|---|
| `target/docker-compose.yml` (`shoplite`) | api-gateway, user-service, order-service, payment-service; `users` on demand | the company's system; two settings point it at ATG for the review: `MESH_PROXY` and `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `docker-compose.yml` (`atg`) | atg-proxy (mitmproxy), atg-collector (OpenTelemetry Collector 0.111.0), atg-postgres (PostgreSQL 16), atg (scanner + web) | our platform, attached to `customer-net` |

By hand: start the target (`docker compose -f target/docker-compose.yml up -d --build --wait`), then ATG (`docker compose up -d --build`), send customers (`docker compose -f target/docker-compose.yml run --rm users`) and scan (`docker compose exec atg python docker/scan.py --label vulnerable`). Each scan reads only what the sidecar and the Collector wrote since the previous scan, then clears it from their in-memory buffers. The report pages and exports are written to `output/site/`; the per-phase files stay in memory under http://localhost:8080/live/ until STOP. Guide: `HOW-TO-RUN.md`.

Tested end to end with `sh start.sh` from a clean copy: 407 HTTP flows through the sidecar and 32 span batches through the Collector in the first scan, giving the same findings and attack-path risk as the local demo. That test machine could not reach Docker Hub, so it used locally built stand-ins. For `python:3.12-slim` it used Python 3.12 on Ubuntu 24.04, and for `postgres:16-alpine` PostgreSQL 16 with UTF-8 and the same environment variables. For `otel/opentelemetry-collector-contrib:0.111.0` it used the official 0.111.0 binary from GitHub. A normal machine pulls the official images.

## Ten open-source systems, and other tools

The professor's review asked for real open-source systems in different fields, a comparison with other
tools, and recommendations instead of percentages. `opensource/` holds ten systems at pinned commits:
Online Boutique, Bank of Anthos, Stan's Robot Shop, Acme Air, Spring PetClinic, PiggyMetrics, Lakeside
Mutual, FTGO, Hotel Reservation and Bookinfo. ATG and eight free tools ran on all ten against the same
716 labelled weaknesses (`docs/BENCHMARK_OSS.md`):

| | ATG v1.5 | best Kubernetes scanner (Polaris) | ATG + Checkov |
|---|---:|---:|---:|
| Systems it can run on | 10/10 | 7/10 (no Docker Compose) | 10/10 |
| Labels found | 466/716 (65%) | 331/716 (46%) | 613/716 (86%) |
| API behaviour, inventory | 52/82, 88/88 | 0, 0 | 52/82, 88/88 |
| Deployment configuration | 326/546 (60%) | 331/546 (61%) | |
| Precision | 75% | 95% | |

The code scanners (Bandit, gosec, njsscan) each read one language, 26 of the 65 services together.
`sh start.sh bookinfo` (or `START-Windows.bat bookinfo`) reviews one of them with stand-in services, and
`sh real.sh robot-shop` (or `REAL-Windows.bat robot-shop`) runs seven of them on their real images
(`opensource/real/README.md`). Version 1.5 fixed gaps that v1.4 showed on these systems, so read its
numbers with the caveat in `docs/BENCHMARK_OSS.md`; v1.4 found 337/716 (47%).

## Point it at a real system

With Docker: see "Review another system" in [HOW-TO-RUN.md](HOW-TO-RUN.md). The company points its traffic and spans at ATG, and ATG gets the company's network name, gateway and config folder through `TARGET_NETWORK`, `TARGET_GATEWAY` and `TARGET_CONFIG`.

Without Docker, only `extractor.yaml` changes: `target.service_map`, capture files (mitmproxy `.jsonl` or `.har`), spec URLs or files, manifest folders, gateway route files, trace files. Phases 2-4 need no configuration. `realcheck/extractor-crapi-real.yaml` is a worked example.

## Layout

```
extractor/            Phase 1 (four extractors, mitmproxy addon, Phase 1 report)
atg/normalizer.py     Phase 2 EUJF + inventory
atg/rules.py          Phase 3 rule engine: 27 rules with OWASP / CWE / ATT&CK / NIST refs and mitigations
atg/analysis.py       Phase 3 vulnerability analyzer, dependency analyzer, threat graph, APCR, risk propagation, fix plan
atg/graphstore.py     graph store (SQLite / PostgreSQL) + recursive attack path SQL
atg/dashboard.py      Phase 4 dashboard
atg/export.py         Phase 4 exports: GraphML, node-link JSON, SARIF 2.1.0, SVG
atg/hardening.py      Phase 4 risk and hardening report ("What to fix, in order")
atg/pipeline.py       runs Phases 1-4 (python -m atg)
demo_target/          ShopLite: services, k8s (vulnerable), k8s-hardened, stale spec, traffic generator
scripts/              run_demo.py (Phases 1-4), run_extractor.py (Phase 1 only)
target/               the company's Docker: ShopLite compose file and Dockerfile
docker-compose.yml    the ATG platform's Docker (sidecar proxy, OTel Collector, PostgreSQL, scanner + web)
docker/               scan.py (one scan, Phases 1-4), serve.py + pages.py (web view), otel-collector.yaml, extractor-target.yaml
START-Windows.bat, start.sh, HOW-TO-RUN.md   start both Dockers and run the before/after review (or: start.sh <company or open-source system>)
REAL-Windows.bat, real.sh                    an open-source system on its real images, reviewed (opensource/real/)
STOP-Windows.bat, stop.sh                    stop both Dockers and delete the review data (pages and exports stay)
CLEAN-Windows.bat, clean.sh                  delete the pages and exports too
bench/                Section IV experiment: miners, replicas, workload, oracle, evaluation, report
bench/testbeds/       ground truth for ShopLite, Train Ticket, crAPI (topology.yaml + source files)
results/              tables, figures, dashboards, and every run's metrics and raw Phase 1 output
realcheck/            kit to repeat Phase 1 on the real crAPI in Docker (Thai guide)
companies/            ten generated companies (company.yaml -> services, manifests, ground truth) and their shared runtime
opensource/           ten open-source systems: system.yaml (operations, calls, labels), fetch.py, build.py, config_labels.py, real/
docs/                 PAPER_MAPPING.md (paper ↔ code), EXPERIMENT.md, THREAT_MODEL.md, RAW_DATA_CONTRACT.md, PHASE1_DESIGN.md,
                      DATA_HANDLING.md, EXPORT_FORMATS.md, LIMITS.md, REVIEW_RESPONSES.md
tests/                unit tests (Phase 1), regression tests on the demo (Phases 2-4), harness checks
```
