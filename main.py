import json
import dns.resolver
import socket
import whois
import asyncio
import os
from sqlalchemy import create_engine
import httpx
import hashlib
from datetime import datetime
from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    Text, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.environ["DB_PORT"])
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

DATABASE_URL = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ================== MODELS ==================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password = Column(String(255))


class DomainCheck(Base):
    __tablename__ = "domain_checks"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    domain = Column(String(255))
    percent = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

    results = relationship("DomainCheckResult", cascade="all, delete")


class DomainCheckResult(Base):
    __tablename__ = "domain_check_results"
    id = Column(Integer, primary_key=True)
    check_id = Column(Integer, ForeignKey("domain_checks.id", ondelete="CASCADE"))
    test_code = Column(Integer)
    test_name = Column(String(100))
    passed = Column(Boolean)
    info = Column(Text)
    extra_info = Column(Text)


Base.metadata.create_all(engine)

# ================== APP ==================
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================== HELPERS ==================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def add_test(ws, results, code, name, passed, info, extra=""):
    data = {
        "type": "test",
        "id": code,
        "name": name,
        "passed": passed,
        "info": info,
        "extra_info": extra or info,
    }
    results.append(data)
    await ws.send_json(data)

async def send_done(ws):
    await ws.send_json({"type": "done", "total": 20})

# ================== AUTH ==================
@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    
    if not user or user.password != data.password:
        raise HTTPException(status_code=401, detail="Login yoki parol xato")

    return {
        "success": True,
        "user_id": user.id,
        "username": user.username
    }
# ================== MAIN LOGIC ==================
# ... oldingi importlar va modellar o'zgarmaydi ...

async def run_all(ws: WebSocket, domain: str, user_id: int, db: Session):
    results = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        https_res = None
        http_res = None
        try:
            https_res = await client.get(f"https://{domain}", headers={"User-Agent": "DomainCheckerBot/1.0"})
            https_status = https_res.status_code
        except Exception as e:
            https_status = None

        try:
            http_res = await client.get(f"http://{domain}", headers={"User-Agent": "DomainCheckerBot/1.0"})
            http_status = http_res.status_code if http_res else None
        except:
            http_status = None

    # 1. DNS mavjudligi
    try:
        dns.resolver.resolve(domain, "A")
        await add_test(ws, results, 1, "DNS mavjudligi", True, "DNS muvaffaqiyatli topildi", "Domen DNS serverlarda mavjud")
    except Exception as e:
        await add_test(ws, results, 1, "DNS mavjudligi", False, "DNS topilmadi", f"Xato: {str(e)}")

    # 2-5. DNS recordlar
    async def record(code, rec, name, description):
        try:
            ans = dns.resolver.resolve(domain, rec)
            records = ", ".join(r.to_text() for r in ans)
            await add_test(ws, results, code, name, True, f"{len(ans)} ta rekord topildi", f"Recordlar: {records}\n{description}")
        except:
            await add_test(ws, results, code, name, False, "Rekord topilmadi", description)

    await record(2, "A", "A rekord (IPv4)", "Saytning IPv4 manzili")
    await record(3, "AAAA", "AAAA rekord (IPv6)", "Saytning IPv6 manzili (kelajak uchun muhim)")
    await record(4, "MX", "MX rekord (Email)", "Email xizmatlari uchun kerak")
    await record(5, "NS", "NS rekord (Name Server)", "Domenni boshqaruvchi serverlar")

    # 6. HTTPS mavjudligi
    if https_res and https_status == 200:
        await add_test(ws, results, 6, "HTTPS ishlaydi", True, "Sayt xavfsiz ulanishni qo‘llab-quvvatlaydi", "SSL/TLS sertifikati faol")
    else:
        await add_test(ws, results, 6, "HTTPS ishlaydi", False, "HTTPS ishlamaydi", "Sayt faqat HTTP orqali ishlaydi — xavfsiz emas")

    # 7. HTTP → HTTPS redirect
    redirect_good = False
    if http_res:
        if http_res.status_code in (301, 302, 303, 307, 308) and http_res.headers.get("Location", "").startswith("https://"):
            redirect_good = True
    await add_test(ws, results, 7, "HTTP → HTTPS yo‘naltirish", redirect_good, 
                   "Foydalanuvchilar avtomatik HTTPS ga o‘tadi" if redirect_good else "Yo‘naltirish yo‘q yoki noto‘g‘ri",
                   "Hackerlik hujumlaridan himoya qiladi")

    # 8-12. Xavfsizlik headerlari
    headers = {
        8: ("Strict-Transport-Security", "HSTS", "Brauzerni faqat HTTPS bilan ishlashga majbur qiladi"),
        9: ("Content-Security-Policy", "CSP", "XSS va boshqa inyeksiya hujumlaridan himoya"),
        10: ("X-Frame-Options", "Clickjacking himoyasi", "Sayt iframe ichida ochilishini oldini oladi"),
        11: ("X-Content-Type-Options", "MIME sniffing himoyasi", "Fayl turini noto‘g‘ri taxmin qilishni oldini oladi"),
        12: ("Referrer-Policy", "Referrer ma'lumoti", "Foydalanuvchi maxfiyligini himoya qiladi")
    }

    if https_res:
        for code, (header, short, desc) in headers.items():
            value = https_res.headers.get(header)
            passed = value is not None
            await add_test(ws, results, code, short, passed, value or "Yo‘q", desc)
    else:
        for code, (_, short, desc) in headers.items():
            await add_test(ws, results, code, short, False, "HTTPS yo‘q", desc)

    # 13-14. Whois va yoshi
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = datetime.now().year - created.year
            await add_test(ws, results, 13, "Domen ro‘yxatga olingan", True, f"{created.date()}", f"Registrar: {w.registrar or 'Nomaʼlum'}")
            await add_test(ws, results, 14, "Domen yoshi", age >= 1, f"{age} yil", "Eski domenlar ko‘proq ishonchli hisoblanadi")
        else:
            raise Exception("Ma'lumot topilmadi")
    except:
        await add_test(ws, results, 13, "Domen ro‘yxatga olingan", False, "Ma'lumot topilmadi", "Whois server javob bermadi")
        await add_test(ws, results, 14, "Domen yoshi", False, "Aniqlanmadi", "Yoshni hisoblash imkonsiz")

    # 15. Sayt tezligi
    if https_res:
        speed = https_res.elapsed.total_seconds()
        passed = speed < 2
        await add_test(ws, results, 15, "Sahifa yuklanish tezligi", passed, f"{speed:.2f} sekund", "Google reytingiga taʼsir qiladi (<2s ideal)")
    else:
        await add_test(ws, results, 15, "Sahifa yuklanish tezligi", False, "HTTPS yo‘q", "Tezlikni o‘lchash imkonsiz")

    # 16. IP manzil
    try:
        ip = socket.gethostbyname(domain)
        await add_test(ws, results, 16, "IP manzil", True, ip, "Domen IP ga muvaffaqiyatli bog‘langan")
    except:
        await add_test(ws, results, 16, "IP manzil", False, "Topilmadi", "DNS yoki tarmoq muammosi bo‘lishi mumkin")

    # 17. DNSSEC
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        await add_test(ws, results, 17, "DNSSEC himoyasi", True, "Faol", "DNS soxtalashtirishdan himoya qiladi")
    except:
        await add_test(ws, results, 17, "DNSSEC himoyasi", False, "Yo‘q", "Hujumlarga ochiqroq")

    # 18. TXT rekord (SPF/DMARC)
    try:
        ans = dns.resolver.resolve(domain, "TXT")
        txt_records = [r.to_text().strip('"') for r in ans]
        has_spf = any("v=spf1" in t for t in txt_records)
        has_dmarc = any(t.startswith("v=DMARC1") for t in txt_records)
        passed = has_spf or has_dmarc
        info = []
        if has_spf: info.append("SPF mavjud")
        if has_dmarc: info.append("DMARC mavjud")
        await add_test(ws, results, 18, "Email autentifikatsiyasi (SPF/DMARC)", passed, ", ".join(info) or "Yo‘q", "Email soxtalashtirishdan himoya qiladi")
    except:
        await add_test(ws, results, 18, "Email autentifikatsiyasi (SPF/DMARC)", False, "TXT rekord yo‘q", "Spam va phishing xavfi yuqori")

    # 19. CAA rekord (SSL sertifikat nazorati)
    try:
        dns.resolver.resolve(domain, "CAA")
        await add_test(ws, results, 19, "CAA rekord (Sertifikat nazorati)", True, "Mavjud", "Faqat ruxsat etilgan CA lar sertifikat bera oladi")
    except:
        await add_test(ws, results, 19, "CAA rekord (Sertifikat nazorati)", False, "Yo‘q", "Har qanday CA sertifikat bera oladi")

    # 20. Robots.txt mavjudligi
    try:
        robots_res = await client.get(f"https://{domain}/robots.txt")
        passed = robots_res.status_code == 200
        await add_test(ws, results, 20, "robots.txt fayli", passed, "Mavjud" if passed else "Yo‘q", "Qidiruv tizimlari uchun ko‘rsatma beradi")
    except:
        await add_test(ws, results, 20, "robots.txt fayli", False, "Yo‘q yoki xato", "Sayt qidiruvda to‘liq indekslanmasligi mumkin")

    await send_done(ws)

    passed_count = len([r for r in results if r["passed"]])
    percent = int((passed_count / 20) * 100)

    check = DomainCheck(user_id=user_id, domain=domain, percent=percent)
    db.add(check)
    db.commit()
    db.refresh(check)

    for r in results:
        db.add(DomainCheckResult(
            check_id=check.id,
            test_code=r["id"],
            test_name=r["name"],
            passed=r["passed"],
            info=r["info"],
            extra_info=r["extra_info"]
        ))
    db.commit()
# Qolgan qismi o'zgarmaydi (history API, websocket, run)
# ================== HISTORY API ==================
@app.get("/history/{user_id}")
def history(user_id: int, db: Session = Depends(get_db)):
    return db.query(DomainCheck).filter_by(user_id=user_id).order_by(DomainCheck.created_at.desc()).all()

@app.get("/history/view/{check_id}")
def view(check_id: int, db: Session = Depends(get_db)):
    return db.query(DomainCheckResult).filter_by(check_id=check_id).order_by(DomainCheckResult.test_code).all()

@app.delete("/history/{check_id}")
def delete(check_id: int, db: Session = Depends(get_db)):
    db.query(DomainCheck).filter_by(id=check_id).delete()
    db.commit()
    return {"status": "deleted"}

# ================== WEBSOCKET ==================
@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws.accept()
    db = SessionLocal()
    try:
        while True:
            data = await ws.receive_json()
            await run_all(ws, data["domain"], data["user_id"], db)
    except WebSocketDisconnect:
        pass
    finally:
        db.close()

# ================== RUN ==================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)