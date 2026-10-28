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

- **Windows:** double-click `START-Windows.bat`; stop with `STOP-Windows.bat`
- **macOS / Linux:** `sh start.sh`; stop with `sh stop.sh`
- **Thai guide:** [HOW-TO-RUN.md](HOW-TO-RUN.md)

The first build takes a few minutes. After that, each start runs ShopLite, a demo shop of four microservices, through all four phases twice: once as shipped and once with the recommended fixes applied. About a minute later the home page at http://localhost:8080 shows the threat graph and the before/after numbers. Attack-path risk drops from 472 to 13.5.

![Home page with a preview of the threat graph and the before/after table](docs/images/home.png)

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
```

## สรุปภาษาไทย

แพ็กนี้มีสองส่วน คือตัวระบบที่รันได้ครบ 4 phase และชุดทดลองที่วัดผลทุก phase เทียบกับ ground truth ผลทั้งหมดอยู่ใน `results/tables.md` (20 ตาราง) และ `results/figures/` (9 รูป) วิธีทดลองกับข้อจำกัดอยู่ใน `docs/EXPERIMENT.md`

### โชว์เพื่อนยังไง

1. **ด้วย Docker (ง่ายสุด):** Windows ดับเบิลคลิก `START-Windows.bat`, Mac/Linux `sh start.sh` หรือ `docker compose up --build` แล้วเปิด http://localhost:8080 หน้าแรกคือ threat graph พร้อมผลก่อน/หลังแก้ วิธีละเอียดอยู่ใน `HOW-TO-RUN.md`
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

### ระวังเรื่องตัวเลขใน draft เดิม

ตัวเลขใน draft ของ paper ที่เคยเขียนไว้ (F1 1.0, precision 93.5%, 36 วินาที, RAM 1.7 GB, ระบบทดสอบ Sock Shop / Online Boutique) ไม่ได้มาจากการทดลองชุดนี้ ให้เปลี่ยนเป็นตัวเลขใน `results/tables.md` และเปลี่ยนชื่อระบบทดสอบเป็น ShopLite, Train Ticket และ crAPI

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
| `results/figures/*.png` | 9 figures |
| `results/dashboards/*.html` | Phase 4 output for every testbed and condition |
| `docs/EXPERIMENT.md` | method, oracle, metric definitions, the nine fixes, threats to validity |
| `docs/THREAT_MODEL.md` | node and edge types, scoring, APCR, propagation, rule limitations |

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

Two containers: `atg` runs ShopLite's four services, mitmproxy and Phases 1-4 (vulnerable, then hardened) and serves the pages; `postgres` is the graph store. The home page opens on the threat graph, with links to both dashboards, the Phase 1 reports and the Section IV results. Everything is also written to `output/site/`. Thai guide: `HOW-TO-RUN.md`.

Tested end to end with `docker compose up --build` from a clean copy. That test machine could not reach Docker Hub, so it used locally built stand-ins for `python:3.12-slim` (Python 3.12 on Ubuntu 24.04) and `postgres:16-alpine` (PostgreSQL 16, UTF-8, same environment variables); a normal machine pulls the official images.

## Point it at a real system

Only `extractor.yaml` changes: `target.service_map`, capture files (mitmproxy `.jsonl` or `.har`), spec URLs or files, manifest folders, gateway route files, trace files. Phases 2-4 need no configuration. `realcheck/extractor-crapi-real.yaml` is a worked example.

## Layout

```
extractor/            Phase 1 (four extractors, mitmproxy addon, Phase 1 report)
atg/normalizer.py     Phase 2 EUJF + inventory
atg/rules.py          Phase 3 rule engine: 27 rules with OWASP / CWE / ATT&CK / NIST refs and mitigations
atg/analysis.py       Phase 3 vulnerability analyzer, dependency analyzer, threat graph, APCR, risk propagation, fix plan
atg/graphstore.py     graph store (SQLite / PostgreSQL) + recursive attack path SQL
atg/dashboard.py      Phase 4 dashboard
atg/pipeline.py       runs Phases 1-4 (python -m atg)
demo_target/          ShopLite: services, k8s (vulnerable), k8s-hardened, stale spec, traffic generator
scripts/              run_demo.py (Phases 1-4), run_extractor.py (Phase 1 only)
docker/serve.py       what the Docker image runs: both scenarios, the pages, a web server on port 8080
Dockerfile, docker-compose.yml, START-Windows.bat, start.sh, HOW-TO-RUN.md   running it with Docker
bench/                Section IV experiment: miners, replicas, workload, oracle, evaluation, report
bench/testbeds/       ground truth for ShopLite, Train Ticket, crAPI (topology.yaml + source files)
results/              tables, figures, dashboards, and every run's metrics and raw Phase 1 output
realcheck/            kit to repeat Phase 1 on the real crAPI in Docker (Thai guide)
docs/                 EXPERIMENT.md, THREAT_MODEL.md, RAW_DATA_CONTRACT.md, PHASE1_DESIGN.md
tests/                unit tests (Phase 1), regression tests on the demo (Phases 2-4), harness checks
```
