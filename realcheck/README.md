# ตรวจกับ crAPI ตัวจริง (ขั้นยืนยันผล)

ผลหลักใน `results/` วัดจาก replica ที่สร้างจาก source code ของ crAPI ขั้นนี้คือการเอา extractor ตัวเดียวกันไปจับ crAPI ตัวจริงที่รันด้วย Docker บนเครื่องของคุณ แล้วดูว่าผลยังตรงกับ ground truth อยู่ไหม ถ้า replica กับของจริงให้ผลใกล้กัน ข้อจำกัดเรื่อง "replica ไม่มี business logic" ก็มีน้ำหนักน้อยลง

สิ่งที่ได้จากขั้นนี้:
- precision ของ inventory บนระบบจริง
- เส้นทาง (path) ที่ระบบจริงตอบ แต่ไม่มีใน ground truth ซึ่งอาจเป็นจุดที่ miner พลาด
- การเดาเรื่อง auth ถูกกี่ตัว และ shadow API ที่เจอจริง

ข้อจำกัดที่ต้องรู้ก่อน: crAPI ไม่มี OpenTelemetry จึงไม่มีแหล่ง Traces และไม่มี access log ของแต่ละ service ให้อ่าน การนับว่า endpoint ไหน "ถูกเรียก" จึงอิงจากหลักฐานใน traffic เอง

## สิ่งที่ต้องมี

- Docker Desktop (Windows ใช้แบบ WSL 2) และ RAM ว่างประมาณ 6 GB, ดิสก์ว่างประมาณ 10 GB
- โปรเจกต์นี้บนเครื่อง ที่เคยรัน `python scripts/run_demo.py` ผ่านแล้ว (แปลว่า mitmproxy ติดตั้งแล้ว)

## ขั้นที่ 1: เปิด crAPI ด้วย Docker

เปิด PowerShell หน้าต่างแรก:

```powershell
cd $HOME\Downloads
Invoke-WebRequest https://github.com/OWASP/crAPI/archive/refs/heads/main.zip -OutFile crapi.zip
Expand-Archive crapi.zip -DestinationPath . -Force
cd crAPI-main\deploy\docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```

รอ 2 ถึง 5 นาที แล้วเช็กด้วย `docker compose ps` จนทุกตัวขึ้น `healthy` หรือ `running` จากนั้นเปิด http://localhost:8888 ในเบราว์เซอร์ ถ้าเห็นหน้า login ของ crAPI แปลว่าพร้อม

หมายเหตุ: ground truth ขุดมาจาก commit `b5fc307f3e` (กันยายน 2026) แต่ Docker image เป็น tag `latest` ถ้า crAPI ออกเวอร์ชันใหม่หลังจากนั้น ผลอาจต่างเพราะตัวระบบเปลี่ยน ให้จดวันที่ที่รันไว้ในรายงานด้วย

## ขั้นที่ 2: เปิดตัวดักจับ traffic

เปิด PowerShell หน้าต่างที่สอง ไปที่โฟลเดอร์โปรเจกต์ (เปิด venv ด้วยถ้าเคยใช้):

```powershell
cd D:\api-threat-graph          # เปลี่ยนเป็นที่อยู่โปรเจกต์ของคุณ
python realcheck/capture.py --fresh
```

ปล่อยหน้าต่างนี้ไว้ มันจะรับ traffic ที่พอร์ต 9888 แล้วส่งต่อไป crAPI ที่ 8888

## ขั้นที่ 3: ใช้งาน crAPI ผ่านพอร์ต 9888

สำคัญ: เข้าที่ **http://localhost:9888** เท่านั้น ถ้าเข้า 8888 ตรง ๆ จะไม่มีอะไรถูกบันทึก

ทำตามรายการนี้แบบผู้ใช้ทั่วไป (ข้อมูลบัญชีให้ตั้งขึ้นเองตอนกรอกฟอร์ม ไม่ต้องใช้ข้อมูลจริง):

1. Sign up สร้างบัญชี แล้ว Login
2. หน้า Dashboard: กด Add a Vehicle ระบบจะส่ง VIN กับ PIN ไปทางอีเมล เปิด MailHog ที่ http://localhost:8025 (แท็บแยก ไม่ต้องผ่าน 9888) เอาค่ามากรอก
3. กด Refresh Location ของรถ
4. Contact Mechanic ส่งคำขอซ่อมหนึ่งครั้ง แล้วเปิดดูรายการคำขอ
5. Shop: ดูสินค้า ซื้อหนึ่งชิ้น เปิด Past Orders แล้วลองกดคืนสินค้า (Return)
6. ใส่ coupon ที่หน้า Shop (ใส่ค่าอะไรก็ได้ ระบบจะตอบว่าใช้ไม่ได้ ก็ยังนับเป็น traffic)
7. Community: เปิดดูโพสต์ สร้างโพสต์ใหม่ แล้ว comment หนึ่งครั้ง
8. Profile: เปลี่ยนรูปโปรไฟล์ อัปโหลดวิดีโอสั้น ๆ แล้วลองเปลี่ยนชื่อวิดีโอ
9. Logout แล้วกด Back ในเบราว์เซอร์สักสองสามหน้า (จะได้ request ที่ไม่มี token ซึ่งใช้วัดการเดาเรื่อง auth)
10. Login ใหม่อีกครั้ง และลอง Forgot Password หนึ่งรอบ (OTP อยู่ใน MailHog)

ใช้เวลาราว 10 ถึง 15 นาที ทำซ้ำบางข้อได้ ยิ่งกดหลายหน้า ยิ่งได้ endpoint มาก

## ขั้นที่ 4: หยุดดักจับ แล้วรัน extractor

กลับไปหน้าต่างที่สอง กด `Ctrl+C` แล้วรัน:

```powershell
python -m extractor --config realcheck/extractor-crapi-real.yaml
python realcheck/score_real.py
```

ผลจะอยู่ที่ `realcheck/out/real_vs_gt.md` (เปิดด้วย VS Code หรือ Notepad ได้) และ `realcheck/out/report.html` คือรายงาน Phase 1 แบบเดียวกับตอน demo

## ขั้นที่ 5: ปิด crAPI

```powershell
cd $HOME\Downloads\crAPI-main\deploy\docker
docker compose down -v
```

## อ่านผลยังไง

- **Precision** ใกล้ 1 แปลว่าแทบทุกรายการใน inventory ตรงกับ endpoint จริงใน source code
- **Documented recall** คือสัดส่วน endpoint ในสเปกที่ inventory มี (มาจากไฟล์ spec เป็นหลัก จึงควรสูงเสมอ)
- **Seen, undocumented** คือ shadow API ที่เห็นใน traffic จริง ตัวเลขนี้ขึ้นกับว่าคุณกดหน้าไหนบ้าง
- **Entries with no match** ทุกบรรทัดควรเปิด source ของ crAPI ดูว่าเป็นอะไร ถ้าเป็น endpoint จริงที่ miner ไม่เจอ ให้บันทึกไว้ เพราะแปลว่า ground truth ของเราขาด และต้องแก้ `bench/miners/crapi.py`
- เทียบกับบรรทัด "Replica, same sources, condition C2" ถ้าตัวเลขใกล้กัน ก็เขียนในรายงานได้ว่าผลของ replica ยืนยันกับระบบจริงแล้ว ถ้าห่างกันมาก ให้อธิบายจากรายการที่ไม่ match

## ถ้าเจอปัญหา

- `mitmdump not found`: รัน `pip install mitmproxy` ใน venv เดียวกับที่ใช้รันโปรเจกต์
- หน้าเว็บที่ 9888 โหลดไม่ขึ้น: เช็กว่า http://localhost:8888 เปิดได้ก่อน ถ้า 8888 ก็ไม่ขึ้น แปลว่า crAPI ยังไม่พร้อม รอเพิ่มหรือดู `docker compose logs crapi-web`
- Chatbot ใช้ไม่ได้: ปกติ เพราะต้องมี OpenAI key ข้ามไปได้เลย
- `score_real.py` บอกว่าไม่มี output: ยังไม่ได้รัน `python -m extractor ...` ในขั้นที่ 4
