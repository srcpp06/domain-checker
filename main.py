import dns.resolver
import socket
import ssl
import whois
import asyncio
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketDisconnect

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
async def add_test(ws: WebSocket, id: int, name: str, passed: bool, info: str, extra_info: str = ""):
    await ws.send_json({
        "type": "test",
        "id": id,
        "name": name,
        "passed": passed,
        "info": info,
        "extra_info": extra_info or info
    })

async def send_done(ws: WebSocket):
    await ws.send_json({
        "type": "done",
        "total": 20
    })

# ================== LOW LEVEL ==================
def get_ssl_info(domain: str):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert(), ssock.version()

async def get_whois(domain: str):
    return await asyncio.to_thread(whois.whois, domain)

# ================== TESTS ==================
async def run_all(ws: WebSocket, domain: str):

    # ---- HTTP / HTTPS ----
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        try:
            https_res = await client.get(f"https://{domain}")
        except:
            https_res = None

        try:
            http_res = await client.get(f"http://{domain}")
        except:
            http_res = None

    # ---- DNS ----
    try:
        answers = dns.resolver.resolve(domain, "A")
        await add_test(ws, 1, "DNS mavjudligi", True, "DNS topildi",
                       ", ".join(r.to_text() for r in answers))
    except Exception as e:
        await add_test(ws, 1, "DNS mavjudligi", False, "DNS topilmadi", str(e))

    await _record(ws, domain, "A", 2, "A record", "IPv4 mavjud", "IPv4 yo‘q")
    await _record(ws, domain, "AAAA", 3, "AAAA record", "IPv6 mavjud", "IPv6 yo‘q")
    await _record(ws, domain, "MX", 4, "MX record", "Email server mavjud", "MX yo‘q")
    await _record(ws, domain, "NS", 5, "NS record", "NS mavjud", "NS yo‘q")

    # ---- HTTPS ----
    if https_res:
        await add_test(ws, 6, "HTTPS ishlashi", True, "HTTPS ishlaydi",
                       f"Status: {https_res.status_code}")
    else:
        await add_test(ws, 6, "HTTPS ishlashi", False, "HTTPS ochilmadi")

    # ---- HTTP → HTTPS ----
    if http_res:
        await add_test(ws, 7, "HTTP → HTTPS redirect",
                       http_res.status_code in (301, 302),
                       "Redirect tekshirildi",
                       f"Status: {http_res.status_code}")
    else:
        await add_test(ws, 7, "HTTP → HTTPS redirect",
                       False, "HTTP ochilmadi")

    # ---- SSL / TLS ----
    try:
        cert, tls = await asyncio.to_thread(get_ssl_info, domain)

        await add_test(ws, 8, "SSL sertifikat", True, "SSL mavjud", tls)

        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        valid = exp > datetime.now(timezone.utc)

        await add_test(ws, 9, "SSL muddati", valid, f"Amal qilish muddati: {exp}")
        await add_test(ws, 10, "TLS qo‘llab-quvvatlanadi", True, "TLS mavjud", tls)

    except Exception as e:
        await add_test(ws, 8, "SSL sertifikat", False, "SSL yo‘q", str(e))
        await add_test(ws, 9, "SSL muddati", False, "SSL yo‘q")
        await add_test(ws, 10, "TLS qo‘llab-quvvatlanadi", False, "TLS yo‘q")

    # ---- SECURITY HEADERS ----
    headers = https_res.headers if https_res else {}

    security_headers = [
        (11, "HSTS", "Strict-Transport-Security"),
        (12, "CSP", "Content-Security-Policy"),
        (13, "X-Frame-Options", "X-Frame-Options"),
        (14, "X-Content-Type-Options", "X-Content-Type-Options"),
        (15, "Referrer-Policy", "Referrer-Policy"),
    ]

    for id, name, h in security_headers:
        await add_test(
            ws, id, name,
            h in headers,
            f"{h} tekshirildi",
            headers.get(h, "Yo‘q")
        )

    # ---- WHOIS ----
    try:
        w = await get_whois(domain)
        await add_test(ws, 16, "Whois mavjud", True, "Whois mavjud")

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        await add_test(
            ws, 17, "Domain yoshi",
            created.year < datetime.now().year,
            f"Yaratilgan sana: {created}"
        )
    except Exception as e:
        await add_test(ws, 16, "Whois mavjud", False, "Whois yo‘q", str(e))
        await add_test(ws, 17, "Domain yoshi", False, "Aniqlanmadi")

    # ---- SPEED ----
    if https_res:
        speed = https_res.elapsed.total_seconds()
        await add_test(ws, 18, "Server tezligi",
                       speed < 2,
                       f"{speed:.2f}s")
    else:
        await add_test(ws, 18, "Server tezligi",
                       False, "O‘lchab bo‘lmadi")

    # ---- IP ----
    try:
        ip = socket.gethostbyname(domain)
        await add_test(ws, 19, "IP address", True, "IP topildi", ip)
    except Exception as e:
        await add_test(ws, 19, "IP address", False, "IP topilmadi", str(e))

    # ---- DNSSEC ----
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        await add_test(ws, 20, "DNSSEC", True, "DNSSEC mavjud")
    except:
        await add_test(ws, 20, "DNSSEC", False, "DNSSEC yo‘q")

    # ---- DONE ----
    await send_done(ws)

# ================== RECORD ==================
async def _record(ws, domain, record, id, name, ok, fail):
    try:
        ans = dns.resolver.resolve(domain, record)
        await add_test(ws, id, name, True, ok,
                       ", ".join(r.to_text() for r in ans))
    except Exception as e:
        await add_test(ws, id, name, False, fail, str(e))

# ================== WEBSOCKET ==================
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    print("✅ Client connected")

    try:
        while True:
            data = await ws.receive_json()
            domain = data.get("domain")
            print("📩 Domain:", domain)

            if domain:
                await run_all(ws, domain)

    except WebSocketDisconnect:
        print("🔌 Client disconnected")

    except Exception as e:
        print("❌ WS error:", e)

# ================== RUN ==================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000))
    )
