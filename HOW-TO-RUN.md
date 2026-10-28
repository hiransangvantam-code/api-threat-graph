# วิธีเปิด API Threat Graph ด้วย Docker

เปิดครั้งเดียวได้ครบ: ระบบ ShopLite 4 service จะรันใน Docker แล้วเครื่องมือจะทำครบ 4 phase สองรอบ (ก่อนแก้กับหลังแก้) เก็บ threat graph ลง PostgreSQL แล้วเปิดหน้าเว็บที่มี threat graph ให้ดูเลย

## ต้องมีอะไรก่อน

1. **Docker Desktop**: ดาวน์โหลดที่ https://www.docker.com/products/docker-desktop/ ติดตั้งแล้วเปิดโปรแกรมทิ้งไว้ รอจนมุมล่างซ้ายขึ้นว่า *Engine running*
   - Windows: ตอนติดตั้งถ้าถามเรื่อง WSL 2 ให้กดตกลง และอาจต้อง restart เครื่องหนึ่งครั้ง
2. **อินเทอร์เน็ต**: ครั้งแรกต้องโหลดราว 300 MB ครั้งต่อไปไม่ต้องโหลดแล้ว

## เปิด

**Windows**: ดับเบิลคลิก `START-Windows.bat`
- ถ้าขึ้น "Windows protected your PC" ให้กด *More info* แล้วกด *Run anyway*
- browser จะเปิด http://localhost:8080 ให้เอง หน้าแรกเป็นหน้ารอที่ขึ้นความคืบหน้า พอครบราว 1 นาทีจะเปลี่ยนเป็นหน้า threat graph เอง
- ครั้งแรกต้อง build ก่อน รอ 3-5 นาที

**Mac / Linux**: เปิด Terminal ในโฟลเดอร์นี้แล้วพิมพ์

```sh
sh start.sh
```

**หรือใช้คำสั่ง Docker ตรง ๆ** (ได้ทุกเครื่อง):

```sh
docker compose up --build
```

แล้วเปิด http://localhost:8080 เอง

## จะเห็นอะไร

| หน้า | มีอะไร |
|---|---|
| หน้าแรก (`/`) | ภาพย่อ threat graph กับตารางเทียบก่อนแก้และหลังแก้ (attack-path risk ลดลง 97.1%) |
| `threat-graph.html` | threat graph เต็มจอ คลิก node เพื่อดูรายละเอียดกับ node ที่เชื่อมกัน หรือคลิก attack path ทางขวาเพื่อไล่ดูเส้นทาง |
| `threat-graph-hardened.html` | threat graph หลังแก้ตามคำแนะนำ |
| `dashboard-vulnerable.html` | dashboard เต็ม: risk summary, ช่องโหว่ พร้อมหลักฐานและมาตรฐานอ้างอิง, attack paths, fix plan, API inventory, rule catalog |
| `phase1-report-vulnerable.html` | ผลของ Phase 1 ว่าแต่ละแหล่ง (traffic, OpenAPI, Kubernetes, traces) เจออะไร |
| Experiment results | ผลการทดลองใน Section IV: dashboard ของ crAPI และ Train Ticket, รูปทั้งหมด, ตาราง 1-20 |

## ปิด

- Windows: ดับเบิลคลิก `STOP-Windows.bat`
- Mac / Linux: `sh stop.sh`
- หรือ `docker compose down`

การปิดหน้าต่างดำ (log) **ไม่ได้** หยุดโปรแกรม ต้องใช้ STOP

## ไฟล์ผลลัพธ์

ทุกหน้าถูกเก็บไว้ในโฟลเดอร์ `output/site/` ด้วย ปิด Docker แล้วก็ยังดับเบิลคลิก `output/site/index.html` เปิดดูได้
(เฉพาะ Linux: ไฟล์ใน `output` จะเป็นของ root ถ้าจะลบให้ใช้ `sudo`)

## ดู threat graph ในฐานข้อมูล

ตอนที่ระบบยังเปิดอยู่ เปิด terminal อีกอันในโฟลเดอร์นี้แล้วพิมพ์

```sh
docker compose exec postgres psql -U atg -c "SELECT type, COUNT(*) FROM atg_nodes GROUP BY type;"
```

ตารางที่มี: `atg_runs`, `atg_nodes`, `atg_edges`, `atg_findings`, `atg_paths` ทุกครั้งที่เปิดใหม่จะล้างข้อมูลเก่าแล้วเริ่มจากศูนย์

## ปัญหาที่เจอบ่อย

| อาการ | ทำยังไง |
|---|---|
| `Docker Desktop is not running` | เปิด Docker Desktop รอจนขึ้น Engine running แล้วลองใหม่ |
| `port is already allocated` หรือ 8080 ถูกใช้อยู่ | ปิดโปรแกรมที่ใช้ port 8080 หรือเปลี่ยน port: PowerShell `$env:ATG_PORT=9090; docker compose up --build` (Mac/Linux `ATG_PORT=9090 sh start.sh`) แล้วเปิด http://localhost:9090 |
| หน้าเว็บขึ้นว่า "The run stopped with an error" | หน้านั้นจะแสดง log ท้าย ๆ ให้ดู ลอง STOP แล้ว START ใหม่ ถ้ายังไม่ได้ ส่งไฟล์ `output/logs/docker-run.log` มาดู |
| ช้ามากตอนแรก | ปกติ ครั้งแรกต้องโหลด Python, PostgreSQL และ library ต่าง ๆ |
| แก้โค้ดแล้วอยากเห็นผล | กด START ใหม่ (มี `--build` อยู่แล้ว จะ build เฉพาะส่วนที่เปลี่ยน) |

## โค้ดอยู่ตรงไหน

| โฟลเดอร์ / ไฟล์ | คืออะไร |
|---|---|
| `extractor/` | Phase 1: ตัวดึงข้อมูลจาก 4 แหล่ง |
| `atg/normalizer.py` | Phase 2: รวมเป็น EUJF และทำ API inventory |
| `atg/rules.py` | Phase 3: rule ทั้ง 27 ข้อ |
| `atg/analysis.py`, `atg/graphstore.py` | Phase 3: สร้าง threat graph, หา attack path ด้วย SQL, คำนวณ APCR, fix plan |
| `atg/dashboard.py` | Phase 4: dashboard และหน้า threat graph |
| `demo_target/` | ระบบ ShopLite ที่ใช้ทดสอบ (มีทั้งแบบมีช่องโหว่และแบบแก้แล้ว) |
| `bench/`, `results/` | ชุดทดลองของ Section IV และผลที่ได้ |
| `docker/serve.py` | สิ่งที่ Docker รันตอนเปิด: รันสองรอบ สร้างหน้าเว็บ แล้วเปิดให้ดูที่ port 8080 |
| `Dockerfile`, `docker-compose.yml` | ตั้งค่า Docker (container ของโปรแกรม + container PostgreSQL) |

อยากรัน test ใน Docker: `docker compose run --rm --no-deps atg python -m pytest -q`
