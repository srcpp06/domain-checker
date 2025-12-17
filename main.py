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

# ================= APP =================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= HELPERS =================

def safe_str(val):
    """Har qanday qiymatni frontend uchun toza string qiladi"""
    if val is None:
        return "Mavjud emas"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val)

async def send_test(ws, id, name, passed, info, extra=None):
    await ws.send_json({
        "id": id,
        "name": name,
        "passed": passed,
        "info": info,
        "extra_info": safe_str(extra if extra is not None else info)
    })

# ================= DNS =================

async def dns_tests(ws, domain):
    loop = asyncio.get_running_loop()

    async def resolve(record):
        return await loop.run_in_executor(
            None, dns.resolver.resolve, domain, record
        )

    # DNS mavjudligi
    try:
        a = await resolve("A")
        await send_test(
            ws, 1, "DNS mavjudligi", True,
            "Domen DNS orqali aniqlanadi",
            ", ".join(r.to_text() for r in a)
        )
    except Exception as e:
        await send_test(ws, 1, "DNS mavjudligi", False,
                        "DNS topilmadi", e)

    records = [
        (2, "A", "IPv4 manzillar mavjud", "IPv4 topilmadi"),
        (3, "AAAA", "IPv6 mavjud", "IPv6 topilmadi"),
        (4, "MX", "Email serverlar mavjud", "MX yozuvi yo‘q"),
        (5, "NS", "DNS serverlar mavjud", "NS topilmadi"),
    ]

    for id, rec, ok, fail in records:
        try:
            r = await resolve(rec)
            await send_test(
                ws, id, f"{rec} record", True,
                ok,
                ", ".join(x.to_text() for x in r)
            )
        except Exception as e:
            await send_test(ws, id, f"{rec} record", False, fail, e)

# ================= HTTP / HTTPS =================

async def http_tests(ws, domain):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:

        # HTTPS
        try:
            https = await client.get(f"https://{domain}")
            await send_test(
                ws, 6, "HTTPS ishlashi", True,
                "HTTPS orqali ochiladi",
                f"Status: {https.status_code}"
            )
        except Exception as e:
            https = None
            await send_test(ws, 6, "HTTPS ishlashi", False,
                            "HTTPS ochilmadi", e)

        # HTTP → HTTPS
        try:
            http = await client.get(f"http://{domain}")
            redirected = http.status_code in (301, 302)
            await send_test(
                ws, 7, "HTTP → HTTPS redirect",
                redirected,
                "HTTP so‘rov tekshirildi",
                f"Status: {http.status_code}"
            )
        except:
            pass

        # Security headers
        if https:
            headers = https.headers
            header_tests = [
                (11, "HSTS", "Strict-Transport-Security"),
                (12, "CSP", "Content-Security-Policy"),
                (13, "X-Frame-Options", "X-Frame-Options"),
                (14, "X-Content-Type-Options", "X-Content-Type-Options"),
                (15, "Referrer-Policy", "Referrer-Policy"),
            ]

            for id, name, h in header_tests:
                await send_test(
                    ws, id, name,
                    h in headers,
                    f"{name} tekshirildi",
                    headers.get(h)
                )

            speed = https.elapsed.total_seconds()
            await send_test(
                ws, 18, "Server tezligi",
                speed < 2,
                f"Javob vaqti: {speed:.2f}s",
                f"{speed:.2f}s"
            )

# ================= SSL =================

def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert(), ssock.version()

async def ssl_tests(ws, domain):
    try:
        cert, tls = await asyncio.to_thread(get_ssl_info, domain)

        await send_test(ws, 8, "SSL sertifikat", True,
                        "SSL sertifikat mavjud", tls)

        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        valid = exp > datetime.now(timezone.utc)

        await send_test(
            ws, 9, "SSL muddati",
            valid,
            f"Amal qilish muddati: {exp.date()}",
            exp
        )

        await send_test(ws, 10, "TLS qo‘llab-quvvatlanadi",
                        True, "TLS faol", tls)

    except Exception as e:
        await send_test(ws, 8, "SSL sertifikat", False,
                        "SSL topilmadi", e)

# ================= WHOIS =================

async def whois_tests(ws, domain):
    try:
        w = await asyncio.to_thread(whois.whois, domain)

        await send_test(
            ws, 16, "Whois mavjud", True,
            "Whois ma’lumotlari olindi",
            f"Registrar: {safe_str(w.registrar)}"
        )

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        await send_test(
            ws, 17, "Domain yoshi",
            bool(created),
            f"Yaratilgan sana: {created.date()}",
            created
        )
    except Exception as e:
        await send_test(ws, 16, "Whois mavjud", False,
                        "Whois topilmadi", e)

# ================= IP / DNSSEC =================

async def ip_test(ws, domain):
    try:
        ip = socket.gethostbyname(domain)
        await send_test(ws, 19, "IP address",
                        True, "IP aniqlandi", ip)
    except Exception as e:
        await send_test(ws, 19, "IP address",
                        False, "IP topilmadi", e)

async def dnssec_test(ws, domain):
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        await send_test(ws, 20, "DNSSEC",
                        True, "DNSSEC mavjud")
    except:
        await send_test(ws, 20, "DNSSEC",
                        False, "DNSSEC mavjud emas")

# ================= RUN ALL =================

async def run_all(ws, domain):
    await asyncio.gather(
        dns_tests(ws, domain),
        http_tests(ws, domain),
        ssl_tests(ws, domain),
        whois_tests(ws, domain),
        ip_test(ws, domain),
        dnssec_test(ws, domain),
    )

# ================= WEBSOCKET =================

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            data = await ws.receive_json()
            domain = data.get("domain")
            if domain:
                await run_all(ws, domain)
    except:
        await ws.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000))
    )
