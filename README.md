# API Threat Graph (ATG)

Automatic API security design review for microservices using threat graph analysis.

ATG runs next to a test deployment of a microservice system and reviews its API design. It reads four kinds of
evidence: the traffic between the services (through a sidecar proxy), their distributed traces (through an
OpenTelemetry Collector), their API documents, and their Kubernetes, Docker Compose and gateway files. From
these it builds one API inventory, applies 27 security rules mapped to the OWASP API Security Top 10, builds a
threat graph, ranks attack paths and writes a fix plan for the system's own technology. No data leaves the
machine it runs on.

This repository is the source code of the SIIT senior project report *Automatic API Security Design Review for
Microservices Using Threat Graph Analysis* (Phanapon Maneechot, Atiwat Thanapatsiri, Hiran Sanguantam, Sunya
Nuchapong; advisor Somchart Fugkeaw). The report is in [`paper/`](paper/): `ATG-Full-Report.pdf`,
`ATG-Full-Report.docx` and its LaTeX source.

![Threat graph page: columns from attacker to impact, attack paths ranked by APCR on the right](docs/images/threat-graph.png)

**Contents:** [Requirements](#requirements) · [Install](#install) · [Run](#run) · [Test](#test) ·
[Reproduce the evaluation](#reproduce-the-evaluation-section-v) · [Run without Docker](#run-without-docker-python) ·
[Repository layout](#repository-layout) · [Troubleshooting](#troubleshooting) · [สรุปภาษาไทย](#สรุปภาษาไทย)

## Requirements

| What | Version | Needed for |
|---|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows 10/11 with WSL 2, macOS) or Docker Engine with Compose v2 (Linux) | Compose v2 | running ATG and the systems it reviews |
| Python | 3.12 or newer (tested with 3.12 and 3.13) | the tests, and running ATG without Docker |
| Internet access | first run only | Docker base images, and each reviewed system's code from GitHub at a pinned commit |
| Free resources | about 8 GB of memory and 10 GB of disk for Docker | |

Start Docker Desktop before running anything; it must show "Engine running".

## Install

```bash
git clone https://github.com/hiransangvantam-code/api-threat-graph.git
cd api-threat-graph
```

or download the repository as a ZIP from GitHub (Code → Download ZIP) and extract it.

There is nothing to compile. The executables are the start and stop scripts in the top folder
(`*-Windows.bat` for Windows, `*.sh` for macOS and Linux); they build the Docker images the first time they run,
which takes 5 to 10 minutes.

## Run

| | Windows (PowerShell in the project folder) | macOS / Linux (terminal in the project folder) |
|---|---|---|
| Review a system | `.\START-Windows.bat` | `sh start.sh` |
| Review another system | `.\START-Windows.bat bookinfo` | `sh start.sh bookinfo` |
| Stop, and delete the review data | `.\STOP-Windows.bat` | `sh stop.sh` |
| Delete the report pages too | `.\CLEAN-Windows.bat` (type `YES`) | `sh clean.sh` (type `YES`) |

With no name, START reviews **Bank of Anthos**. The ten systems are `online-boutique`, `bank-of-anthos`,
`robot-shop`, `acme-air`, `petclinic`, `piggymetrics`, `lakeside-mutual`, `ftgo`, `hotel-reservation` and
`bookinfo` (described in [`opensource/README.md`](opensource/README.md)).

START runs four steps and prints each one:

1. downloads the system's code at its pinned commit (first time only), because ATG reads its real deployment files;
2. starts the system under review (the company's Docker) and the ATG platform (ATG's Docker);
3. runs the system's users, whose requests go through ATG's sidecar;
4. scans once (Phases 1 to 4) and opens http://localhost:8080.

When it prints `Done`, open or refresh http://localhost:8080. For Bank of Anthos the scan reports 15 APIs, 45
findings, 99 attack paths and an attack-path risk of 316.55. The pages are:

| Page | What it shows |
|---|---|
| Home | the threat graph preview, the four phases, every scan, export links |
| Threat graph | the graph from attacker to impact; click a node or an attack path |
| Dashboard | API inventory, risk summary, top vulnerabilities, attack paths, fix plan |
| Hardening report | what to fix, in order, written for the system's own gateway, Kubernetes or framework, with a check for each fix |
| Exports | the threat graph as GraphML, JSON, SARIF and SVG (`output/site/exports/`) |

![The company's Docker and the ATG Docker: traffic through the sidecar, spans to the Collector, OpenAPI probe, manifests read-only, Phases 1-4, PostgreSQL](docs/images/two-dockers.png)

The services that run are stand-ins built from each system's code (same names, ports, operations, calls and
authentication checks); everything ATG reads from files is the real system. `REAL-Windows.bat robot-shop`
(`sh real.sh robot-shop`) runs seven of the systems on their published images instead
([`opensource/real/README.md`](opensource/real/README.md)). The step-by-step guide, including how to point ATG
at your own system, is [HOW-TO-RUN.md](HOW-TO-RUN.md).

## Test

```bash
python -m venv venv
# Windows PowerShell:  .\venv\Scripts\Activate.ps1
# macOS / Linux:       source venv/bin/activate
pip install -r requirements.txt

python scripts/run_demo.py --scenario both    # about 15 s; the regression tests read its output
python -m pytest -q                           # about 2 minutes
```

Expected result: `77 passed, 1 skipped`. The skipped test checks that PostgreSQL gives the same attack paths as
SQLite; it runs when `ATG_TEST_PG` is set to a PostgreSQL URL. The tests cover Phase 1 (each extractor, and API
documents with a base path), Phases 2 to 4 on the ShopLite demo (every planted weakness found, nothing else
reported, no internet attack path to an operation the gateway does not route), the fix planner, the hardening
report, the configuration styles of the development test systems, and the evaluation harness.

## Reproduce the evaluation (Section V)

Every number in Section V of the report comes from two scripts. Run them in this order:

| Step | Windows | macOS / Linux | What it does |
|---|---|---|---|
| 1 | `.\DEMO-ALL-Windows.bat` | `sh demo-all.sh` | reviews the ten systems with ATG one after another and records ATG's time, CPU, memory, network and disk use |
| 2 | `.\BENCH-Windows.bat` | `sh bench.sh` | runs eight free tools (Checkov, Kubescape, kube-linter, Polaris, Spectral, Bandit, gosec, njsscan) on the same systems in one Docker image, scores every tool against the same answer key and opens the comparison page |

The results go to `results/opensource/`: `comparison.html` (the page with every table and chart),
`comparison.md`, `comparison.json` and `figures/`. The answer keys are `opensource/<system>/ground-truth.json`.
After a new run, `python3 paper/gen_sec5.py` rewrites Section V of `paper/main.tex` from the new page. Method
and limits: [docs/BENCHMARK_OSS.md](docs/BENCHMARK_OSS.md).

| Measure | Result (medians per system) |
|---|---|
| 1. Speed | ATG's analysis (Phases 1-4) 0.44 s, whole scan 7.7 s; the file scanners 0.04 s (kube-linter) to 4.1 s (gosec) |
| 2. Computing resources | ATG scan 0.82 s CPU and 144 MB; ATG's four containers 232 MB during a whole review; Checkov 4.1 s and 761 MB |
| 3. Accuracy (712 known weaknesses) | ATG 462 (65%), 75% of its reports correct; best other tool Polaris 349 (49%); ATG + Checkov 611 (86%); ATG lists 189 of 201 operations |
| 4. Systems covered | ATG 10/10; each Kubernetes scanner 7/10; Spectral 3/10; code scanners 3-4/10 |
| 5. Language limits | ATG 65 of 65 services in 8 languages; the three code scanners together 26 of 65 (40%) |

Other experiments are kept but are not in the report: discovery by source and the sidecar's latency
(`bench/oss_eval.py`, `bench/oss_report.py`), OWASP ZAP (`bench/oss_eval.py --zap`; on the BENCH page only with
`python bench/compare_tools.py --with-zap`), the fix experiment (`bench/oss_fixes.py`) and the stress test
(`bench/oss_stress.py`).

## Run without Docker (Python)

After the install steps under [Test](#test):

| Command | What you get |
|---|---|
| `python scripts/run_demo.py --scenario both` | Phases 1-4 on the ShopLite demo, before and after its fixes; open `output/dashboard.html` |
| `python scripts/run_extractor.py` | Phase 1 only: `output/raw/*.json` and `output/report.html` |
| `python -m atg --config extractor.yaml --skip-extract` | Phases 2-4 again on the last extraction |

To review another system without Docker, only `extractor.yaml` changes (capture files, API documents, manifest
folders, gateway route files, trace files); `realcheck/extractor-crapi-real.yaml` is a worked example. The
threat graph goes to SQLite by default; for PostgreSQL, `pip install -r requirements-postgres.txt` and set
`ATG_GRAPH_STORE=postgresql://user:password@host:5432/db`.

## How it works

```
1 EXTRACTOR        mitmproxy · OpenAPI · K8s / Compose / gateway files · OpenTelemetry  -> raw/*.json
2 API NORMALIZER   merge into the Extended Universal JSON Format (EUJF)                 -> eujf.json
                   + API inventory (documented / shadow / zombie / dormant)
3 ANALYSIS & RISK  27 rules · dependency analyzer · threat graph (SQLite or PostgreSQL)  -> analysis.json
                   · attack paths (recursive SQL) · APCR risk · fix plan
4 OUTPUT           dashboard · threat graph page · hardening report · GraphML / JSON / SARIF / SVG exports
```

[docs/PAPER_MAPPING.md](docs/PAPER_MAPPING.md) maps every part of Section III of the report to the code.
What ATG keeps after a review: captured traffic, traces, Phase 1 files and the database stay in memory and are
deleted by STOP; only the report pages and exports are written to `output/site/`, which CLEAN deletes
([docs/DATA_HANDLING.md](docs/DATA_HANDLING.md)).

## Repository layout

```
START-, STOP-, CLEAN-, REAL-Windows.bat   run, stop and clean a review (Windows); start.sh, stop.sh, clean.sh, real.sh (macOS/Linux)
DEMO-ALL-Windows.bat, demo-all.sh         evaluation step 1: ATG on the ten systems
BENCH-Windows.bat, bench.sh               evaluation step 2: the eight tools, scoring, comparison page
docker-compose.yml, Dockerfile, docker/   the ATG platform: sidecar, OpenTelemetry Collector, PostgreSQL, scanner and web view
extractor/                                Phase 1: the four extractors and the mitmproxy addon
atg/                                      Phases 2-4: normalizer (EUJF), rules, analysis (threat graph, APCR, plan),
                                          graph store, dashboard, hardening report, exports, pipeline
opensource/                               the ten systems: system.yaml, answer keys (ground-truth.json), stand-in
                                          compose files, fetch.py (downloads their code), real/ (published images)
bench/                                    evaluation scripts: run_tools.py, compare_tools.py, oss_figures.py, usage.py, ...
results/opensource/                       the evaluation results used in the report
paper/                                    the report: PDF, Word, LaTeX source and figures, and the scripts that build them
tests/                                    unit and regression tests (pytest)
docs/                                     design notes, method, data handling, export formats, limits
scripts/, extractor.yaml                  running ATG without Docker
demo_target/, target/, companies/,        ShopLite and earlier development test systems, used by the tests;
realcheck/, results/ (other folders)      not part of the report's evaluation (docs/DEVELOPMENT_HISTORY.md)
```

## Troubleshooting

| Problem | What to do |
|---|---|
| `Docker is not running` or `Cannot connect to the Docker daemon` | start Docker Desktop and wait for "Engine running" |
| The first start takes long | the first build downloads and builds the images (5 to 10 minutes); later starts take about a minute |
| `Stopped: the download` | the first start of each system downloads its code from GitHub; check the internet connection or proxy and run START again |
| Port 8080 is already in use | run STOP for an earlier review, or close the program that uses port 8080 |
| Windows shows "Windows protected your PC" | click More info, then Run anyway |
| The page still shows an old review | wait for `Done`, then refresh the browser (F5) |
| Start over completely | run CLEAN, then START |

## สรุปภาษาไทย

ATG คือระบบตรวจการออกแบบความปลอดภัยของ API ใน microservices แบบอัตโนมัติ รันคู่กับระบบที่ตรวจโดยไม่ส่งข้อมูลออกนอกเครื่อง อ่านหลักฐาน 4 แหล่ง (traffic ผ่าน sidecar, traces, เอกสาร API, ไฟล์ Kubernetes/Docker Compose/gateway) แล้วสร้าง threat graph จัดลำดับ attack path และเขียนแผนการแก้ไข รายงานฉบับเต็มอยู่ในโฟลเดอร์ `paper/`

- **ติดตั้ง:** ลง Docker Desktop แล้วเปิดให้ขึ้น "Engine running" จากนั้น `git clone` หรือดาวน์โหลด ZIP จาก GitHub
- **รัน:** Windows `.\START-Windows.bat` ส่วน Mac/Linux `sh start.sh` (ค่าเริ่มต้นตรวจ Bank of Anthos ใส่ชื่อระบบอื่นได้ เช่น `bookinfo`) เสร็จแล้วเปิด http://localhost:8080 หยุดด้วย STOP และลบทั้งหมดด้วย CLEAN
- **ทดสอบ:** `pip install -r requirements.txt` แล้ว `python scripts/run_demo.py --scenario both` และ `python -m pytest -q` ผลที่ควรได้คือ `77 passed, 1 skipped`
- **ทำผลการทดลองซ้ำ (Section V):** รัน `DEMO-ALL-Windows.bat` แล้วตามด้วย `BENCH-Windows.bat` ผลอยู่ที่ `results/opensource/comparison.html`
- **ผลโดยย่อ:** ATG หาจุดอ่อนได้ 462/712 (65%) เครื่องมือฟรีที่ดีที่สุด (Polaris) ได้ 349 (49%) ATG รันได้ครบ 10/10 ระบบและทุก 65 services ใน 8 ภาษา วิเคราะห์ 0.44 วินาทีต่อระบบ ใช้ CPU 0.82 วินาทีและหน่วยความจำ 144 MB
