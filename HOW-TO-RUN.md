# วิธีเปิด API Threat Graph ด้วย Docker (2 Docker)

ระบบนี้มี Docker 2 ชุด ตรงกับ Fig. 1 ใน paper

| Docker | คืออะไร | ไฟล์ |
|---|---|---|
| **Docker ของบริษัท (target)** | ระบบที่ถูกตรวจ คือ ShopLite มี 4 microservice (api-gateway, user-service, order-service, payment-service) อยู่บน network ชื่อ `customer-net` | `target/docker-compose.yml` |
| **Docker ของเรา (ATG platform)** | เข้าไปต่อกับ network ของบริษัทแล้วเก็บข้อมูลจาก 4 แหล่ง จากนั้นทำ Phase 1-4 | `docker-compose.yml` |

ใน Docker ของเรามี container 4 ตัว

| Container | ทำอะไร | Phase |
|---|---|---|
| `atg-proxy` | mitmproxy ตั้งเป็น sidecar ขวางหน้า gateway ลูกค้าเข้าผ่านตัวนี้ และ service ของบริษัทก็เรียกหากันผ่านตัวนี้ด้วย | 1 (runtime traffic) |
| `atg-collector` | OpenTelemetry Collector รับ trace ที่ service ของบริษัทส่งมา | 1 (trace) |
| `atg-postgres` | PostgreSQL เก็บ EUJF (ตาราง `atg_eujf`) และ threat graph (`atg_nodes`, `atg_edges`) | 2, 3 |
| `atg` | probe OpenAPI ของ service, อ่าน manifest ของบริษัท แล้วรัน Phase 1-4 และเปิดหน้าเว็บที่ http://localhost:8080 | 1-4 |

ข้อมูลทั้งหมดอยู่ใน network ของบริษัท ไม่มีอะไรถูกส่งออกไปข้างนอก

## ต้องมีอะไรก่อน

1. **Docker Desktop**: ดาวน์โหลดที่ https://www.docker.com/products/docker-desktop/ ติดตั้งแล้วเปิดค้างไว้จนขึ้นว่า *Engine running*
   - Windows: ถ้าถามเรื่อง WSL 2 ให้กดตกลง และอาจต้อง restart เครื่องหนึ่งครั้ง
2. **อินเทอร์เน็ต**: ครั้งแรกต้องโหลด image หลายร้อย MB และต้อง build ใช้เวลา 3-5 นาที ครั้งต่อไปเร็วขึ้นมาก

## เปิด (ทำครบทุกขั้นให้อัตโนมัติ)

**Windows**: ดับเบิลคลิก `START-Windows.bat` ถ้าขึ้น "Windows protected your PC" ให้กด *More info* แล้วกด *Run anyway*

**Mac / Linux**: เปิด Terminal ในโฟลเดอร์นี้แล้วพิมพ์ `sh start.sh`

สคริปต์จะทำ 6 ขั้น และหน้าต่างดำจะบอกว่ากำลังทำขั้นไหน

1. เปิด Docker ของบริษัท (ShopLite เวอร์ชันที่ยังมีช่องโหว่)
2. เปิด Docker ของเรา แล้ว browser จะเปิด http://localhost:8080 ให้เอง ตอนนี้ยังเป็นหน้าสถานะที่ติ๊กให้ดูว่า container ของทั้งสองฝั่งพร้อมแล้ว
3. ลูกค้าจำลองเข้าใช้ร้านค้า โดย traffic วิ่งผ่าน sidecar ของเรา
4. Scan รอบที่ 1 (Phase 1-4) พอเสร็จ หน้าเว็บจะเปลี่ยนเป็น threat graph
5. บริษัท deploy เวอร์ชันที่แก้ช่องโหว่แล้ว และลูกค้าจำลองเข้าใช้อีกรอบ
6. Scan รอบที่ 2 หน้าเว็บจะแสดงตารางเทียบก่อน/หลังแก้ (attack-path risk 472 → 13.5)

ทั้งหมดใช้เวลาราว 2 นาที ไม่นับเวลา build ครั้งแรก

## หน้าเว็บมีอะไร

| หน้า | มีอะไร |
|---|---|
| หน้าแรก | ภาพย่อ threat graph, ตารางก่อน/หลังแก้, การ์ด Phase 1-4 ที่ลิงก์ไปยังผลของแต่ละ phase, ตาราง scan ทุกรอบ, ภาพการเชื่อมต่อของ 2 Docker และผลการทดลอง Section IV |
| `threat-graph.html` | threat graph เต็มจอ คลิก node หรือ attack path ได้ |
| `dashboard-1-vulnerable.html` | dashboard เต็มของ Phase 4: API overview (แยกตามแหล่งข้อมูลและ confidence HIGH/MEDIUM/ZOMBIE), risk summary, top vulnerabilities, attack paths, fix plan |
| `phase1-report-1-vulnerable.html` | สิ่งที่ Phase 1 เจอจากแต่ละแหล่ง |
| `scans/1-vulnerable/eujf.json` | ผลของ Phase 2 ในรูป EUJF ตาม Algorithm 1 ใน paper |
| `scans/1-vulnerable/raw/*.json` | ผลดิบของ Phase 1 แยกตามแหล่ง |

## ปิด

- Windows: ดับเบิลคลิก `STOP-Windows.bat`
- Mac / Linux: `sh stop.sh`

การปิดหน้าต่างดำ**ไม่ได้**หยุด Docker ต้องใช้ STOP เท่านั้น หน้าเว็บของรอบล่าสุดยังเปิดดูได้ที่ `output/site/index.html`

## รันทีละขั้นเอง (ถ้าอยากอธิบายให้อาจารย์ดูทีละ phase)

```sh
docker compose -f target/docker-compose.yml up -d --build --wait     # 1. Docker ของบริษัท
docker compose up -d --build                                           # 2. Docker ของเรา -> http://localhost:8080
docker compose -f target/docker-compose.yml run --rm users             # 3. ลูกค้าเข้าใช้ร้าน (ผ่าน sidecar)
docker compose exec atg python docker/scan.py --label vulnerable       # 4. Phase 1-4
```

ถ้าจะ deploy เวอร์ชันที่แก้แล้ว (PowerShell ใช้ `$env:SHOPLITE_HARDENED="1"; $env:SHOPLITE_MANIFESTS="k8s-hardened"` แทนบรรทัดแรก):

```sh
export SHOPLITE_HARDENED=1 SHOPLITE_MANIFESTS=k8s-hardened
docker compose -f target/docker-compose.yml up -d --wait
docker compose -f target/docker-compose.yml run --rm users
docker compose exec atg python docker/scan.py --label hardened --manifests k8s-hardened
```

## ดูข้อมูลใน PostgreSQL

ตอนที่ระบบยังเปิดอยู่:

```sh
docker compose exec atg-postgres psql -U atg -c "SELECT api_id, method, endpoint, auth, confidence FROM atg_eujf;"
docker compose exec atg-postgres psql -U atg -c "SELECT rel, COUNT(*) FROM atg_edges GROUP BY rel;"
```

คำสั่งแรกแสดง EUJF ของ Phase 2 คำสั่งที่สองแสดง edge ของ threat graph ซึ่งใช้ชื่อตาม eq. (3) ใน paper คือ ROUTES_TO, CALLS, QUERIES, HAS_FINDING

## ปัญหาที่เจอบ่อย

| อาการ | ทำยังไง |
|---|---|
| `Docker Desktop is not running` | เปิด Docker Desktop รอจนขึ้น Engine running แล้วลองใหม่ |
| `network customer-net ... not found` | ต้องเปิด Docker ของบริษัทก่อน (ขั้นที่ 1) แล้วค่อยเปิด Docker ของเรา ซึ่งสคริปต์ START ทำให้อยู่แล้ว |
| port 8080 ถูกใช้อยู่ | ปิดโปรแกรมที่ใช้ port นั้น หรือใช้ `ATG_PORT=9090 sh start.sh` (Mac/Linux) แล้วเปิด http://localhost:9090 ส่วน `START-Windows.bat` ใช้ 8080 เท่านั้น |
| หน้าเว็บขึ้น "The scan stopped with an error" | หน้านั้นจะแสดง log ให้ ลองกด STOP แล้ว START ใหม่ ถ้ายังพังอยู่ให้ส่ง log ในหน้านั้นมาดู |
| ครั้งแรกช้ามาก | ปกติ ครั้งแรกต้องโหลด Python, PostgreSQL, OpenTelemetry Collector และ library ต่าง ๆ |

## โค้ดแต่ละ phase อยู่ตรงไหน

ดูตารางเทียบ paper กับโค้ดได้ที่ `docs/PAPER_MAPPING.md`

| โฟลเดอร์ / ไฟล์ | คืออะไร |
|---|---|
| `target/` | Docker ของบริษัท (compose + Dockerfile) |
| `demo_target/` | โค้ดของ ShopLite, manifest (k8s, k8s-hardened) และ spec file |
| `docker-compose.yml`, `Dockerfile` | Docker ของเรา |
| `docker/scan.py` | การ scan หนึ่งรอบ (Phase 1-4 จากข้อมูลที่เก็บได้ตั้งแต่รอบก่อน) |
| `docker/serve.py`, `docker/pages.py` | หน้าเว็บที่ port 8080 |
| `docker/otel-collector.yaml` | การตั้งค่า OpenTelemetry Collector |
| `docker/extractor-target.yaml` | ชื่อ service และ URL ของระบบที่ตรวจ ถ้าจะตรวจระบบอื่นให้แก้ไฟล์นี้ |
| `extractor/` | Phase 1 |
| `atg/normalizer.py` | Phase 2 (EUJF) |
| `atg/rules.py`, `atg/analysis.py`, `atg/graphstore.py` | Phase 3 |
| `atg/dashboard.py` | Phase 4 |
| `bench/`, `results/` | การทดลองใน Section IV และผลที่ได้ |
