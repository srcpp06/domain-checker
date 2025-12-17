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

app = FastAPI()

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== JSON YUBORISH (FRONTENDGA MOS) =====
async def add_test(websocket, id, name, passed, info, extra_info=None):
    await websocket.send_json({
        "id": id,
        "name": name,
        "passed": passed,
        "info": info,
        "extra_info": extra_info if extra_info else info
    })

# ===== DNS TESTLAR =====
async def test_dns(websocket, domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        await add_test(
            websocket, 1, "DNS mavjudligi", True,
            "Domen DNS orqali aniqlanadi",
            ", ".join(r.to_text() for r in answers)
        )
    except Exception as e:
        await add_test(websocket, 1, "DNS mavjudligi", False, "DNS topilmadi", str(e))


async def test_record(websocket, domain, record, id, name, ok, fail):
    try:
        answers = dns.resolver.resolve(domain, record)
        await add_test(
            websocket, id, name, True,
            ok,
            ", ".join(r.to_text() for r in answers)
        )
    except Exception as e:
        await add_test(websocket, id, name, False, fail, str(e))


# ===== SSL BIR MARTA =====
def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert(), ssock.version()


# ===== WHOIS ASYNC =====
async def get_whois(domain):
    return await asyncio.to_thread(whois.whois, domain)


# ===== BARCHA TESTLAR =====
async def run_all(websocket, domain):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        try:
            https_res = await client.get(f"https://{domain}")
        except:
            https_res = None

        try:
            http_res = await client.get(f"http://{domain}")
        except:
            http_res = None

    # DNS
    await test_dns(websocket, domain)
    await test_record(websocket, domain, "A", 2, "A record", "IPv4 mavjud", "IPv4 topilmadi")
    await test_record(websocket, domain, "AAAA", 3, "AAAA record", "IPv6 mavjud", "IPv6 topilmadi")
    await test_record(websocket, domain, "MX", 4, "MX record", "Email serverlar mavjud", "MX topilmadi")
    await test_record(websocket, domain, "NS", 5, "NS record", "NS mavjud", "NS topilmadi")

    # HTTPS
    if https_res:
        await add_test(
            websocket, 6, "HTTPS ishlashi", True,
            "HTTPS ishlaydi",
            f"Status: {https_res.status_code}"
        )
    else:
        await add_test(websocket, 6, "HTTPS ishlashi", False, "HTTPS ochilmadi")

    # HTTP → HTTPS
    if http_res:
        await add_test(
            websocket, 7, "HTTP → HTTPS redirect",
            http_res.status_code in (301, 302),
            "Redirect tekshirildi",
            f"Status: {http_res.status_code}"
        )

    # SSL / TLS
    try:
        cert, tls_version = await asyncio.to_thread(get_ssl_info, domain)

        await add_test(websocket, 8, "SSL sertifikat", True, "SSL mavjud", tls_version)

        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        valid = exp > datetime.now(timezone.utc)

        await add_test(
            websocket, 9, "SSL muddati", valid,
            f"Amal qilish muddati: {exp}",
            str(exp)
        )

        await add_test(
            websocket, 10, "TLS qo‘llab-quvvatlanadi", True,
            "TLS mavjud",
            tls_version
        )

    except Exception as e:
        await add_test(websocket, 8, "SSL sertifikat", False, "SSL topilmadi", str(e))

    # Security headers
    if https_res:
        headers = https_res.headers
        header_tests = [
            (11, "HSTS", "Strict-Transport-Security"),
            (12, "CSP", "Content-Security-Policy"),
            (13, "X-Frame-Options", "X-Frame-Options"),
            (14, "X-Content-Type-Options", "X-Content-Type-Options"),
            (15, "Referrer-Policy", "Referrer-Policy"),
        ]

        for id, name, header in header_tests:
            await add_test(
                websocket, id, name,
                header in headers,
                f"{header} tekshirildi",
                headers.get(header, "Yo‘q")
            )

    # Whois
    try:
        w = await get_whois(domain)
        await add_test(websocket, 16, "Whois mavjud", True, "Whois mavjud", str(w))

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        await add_test(
            websocket, 17, "Domain yoshi",
            created.year < datetime.now().year,
            f"Yaratilgan sana: {created}",
            str(created)
        )

    except Exception as e:
        await add_test(websocket, 16, "Whois mavjud", False, "Whois topilmadi", str(e))

    # Server speed
    if https_res:
        speed = https_res.elapsed.total_seconds()
        await add_test(
            websocket, 18, "Server tezligi",
            speed < 2,
            f"Javob vaqti: {speed:.2f}s",
            f"{speed:.2f}s"
        )

    # IP
    try:
        ip = socket.gethostbyname(domain)
        await add_test(websocket, 19, "IP address mavjud", True, "IP topildi", ip)
    except Exception as e:
        await add_test(websocket, 19, "IP address mavjud", False, "IP topilmadi", str(e))

    # DNSSEC
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        await add_test(websocket, 20, "DNSSEC", True, "DNSSEC mavjud")
    except:
        await add_test(websocket, 20, "DNSSEC", False, "DNSSEC mavjud emas")


# ===== WEBSOCKET (XATO TUZATILDI) =====
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("✅ Client connected")

    try:
        while True:
            data = await websocket.receive_json()
            domain = data.get("domain")
            print("📩 Domain:", domain)

            if domain:
                await run_all(websocket, domain)

    except Exception as e:
        # ❗ websocket.close() YO‘Q — ASOSIY FIX SHU
        print("❌ WS error:", e)


# ===== RUN =====
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000))
    )
