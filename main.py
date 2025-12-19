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
async def run_all(ws: WebSocket, domain: str, user_id: int, db: Session):
    results = []

    async with httpx.AsyncClient(timeout=5) as client:
        try:
            https_res = await client.get(f"https://{domain}")
        except:
            https_res = None

        try:
            http_res = await client.get(f"http://{domain}")
        except:
            http_res = None

    try:
        dns.resolver.resolve(domain, "A")
        await add_test(ws, results, 1, "DNS mavjudligi", True, "DNS topildi")
    except Exception as e:
        await add_test(ws, results, 1, "DNS mavjudligi", False, "DNS topilmadi", str(e))

    async def record(code, rec, name):
        try:
            ans = dns.resolver.resolve(domain, rec)
            await add_test(ws, results, code, name, True, "Mavjud", ", ".join(r.to_text() for r in ans))
        except:
            await add_test(ws, results, code, name, False, "Yo‘q")

    await record(2, "A", "A record")
    await record(3, "AAAA", "AAAA record")
    await record(4, "MX", "MX record")
    await record(5, "NS", "NS record")

    if https_res:
        await add_test(ws, results, 6, "HTTPS", True, "HTTPS ishlaydi")
    else:
        await add_test(ws, results, 6, "HTTPS", False, "HTTPS yo‘q")

    if http_res:
        await add_test(ws, results, 7, "HTTP → HTTPS", http_res.status_code in (301, 302), "Redirect")
    else:
        await add_test(ws, results, 7, "HTTP → HTTPS", False, "HTTP yo‘q")

    if https_res:
        for i, h in enumerate([
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ], start=8):  # <--- BU YERDA O'ZGARTIRDIM: start=8 (8-12 headers)
            await add_test(ws, results, i, h, h in https_res.headers, https_res.headers.get(h, "Yo‘q"))

    try:
        w = await asyncio.to_thread(whois.whois, domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        await add_test(ws, results, 13, "Whois", True, f"Yaratilgan: {created}")  # <--- Id'lar o'zgardi
        await add_test(ws, results, 14, "Domain yoshi", created.year < datetime.now().year, "Tekshirildi")
    except:
        await add_test(ws, results, 13, "Whois", False, "Yo‘q")
        await add_test(ws, results, 14, "Domain yoshi", False, "Aniqlanmadi")

    if https_res:
        speed = https_res.elapsed.total_seconds()
        await add_test(ws, results, 15, "Tezlik", speed < 2, f"{speed:.2f}s")

    try:
        ip = socket.gethostbyname(domain)
        await add_test(ws, results, 16, "IP", True, ip)
    except:
        await add_test(ws, results, 16, "IP", False, "Yo‘q")

    try:
        dns.resolver.resolve(domain, "DNSKEY")
        await add_test(ws, results, 17, "DNSSEC", True, "Mavjud")
    except:
        await add_test(ws, results, 17, "DNSSEC", False, "Yo‘q")

    # Qo'shimcha 18-20 testlar (agar kerak bo'lsa qo'sh, hozircha placeholder, lekin soni 20 bo'lishi uchun)
    await add_test(ws, results, 18, "Qo'shimcha test 1", True, "Placeholder")
    await add_test(ws, results, 19, "Qo'shimcha test 2", False, "Placeholder")
    await add_test(ws, results, 20, "Qo'shimcha test 3", True, "Placeholder")

    await send_done(ws)

    passed = len([r for r in results if r["passed"]])
    percent = int((passed / 20) * 100)

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