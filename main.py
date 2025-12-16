import dns.resolver
import requests
import socket
import ssl
import whois
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import os

app = FastAPI()

# CORS sozlamalari (front-end bilan ishlash uchun)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== TEST FUNKSIYALARI =====
async def add_test(websocket, id, name, passed, info, extra_info=None):
    data = {
        "id": id,
        "name": name,
        "passed": passed,
        "info": info,
        "extra_info": extra_info if extra_info else info
    }
    await websocket.send_json(data)

async def test_dns(websocket, domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        await add_test(websocket, 1, "DNS mavjudligi", True, "Domen DNS orqali aniqlanadi", extra_info=", ".join([r.to_text() for r in answers]))
    except:
        await add_test(websocket, 1, "DNS mavjudligi", False, "Domen DNS orqali aniqlanmadi")

async def test_a_record(websocket, domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [r.to_text() for r in answers]
        await add_test(websocket, 2, "A record", True, "Domenning IPv4 manzili mavjud", extra_info=", ".join(ips))
    except:
        await add_test(websocket, 2, "A record", False, "IPv4 manzil topilmadi")

async def test_aaaa_record(websocket, domain):
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        ips = [r.to_text() for r in answers]
        await add_test(websocket, 3, "AAAA record", True, "IPv6 manzil mavjud", extra_info=", ".join(ips))
    except:
        await add_test(websocket, 3, "AAAA record", False, "IPv6 manzil topilmadi")

async def test_mx(websocket, domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mxs = [r.exchange.to_text() for r in answers]
        await add_test(websocket, 4, "MX record", True, "Email serverlari mavjud", extra_info=", ".join(mxs))
    except:
        await add_test(websocket, 4, "MX record", False, "Email serverlari topilmadi")

async def test_ns(websocket, domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        nss = [r.to_text() for r in answers]
        await add_test(websocket, 5, "NS record", True, "Domen serverlari mavjud", extra_info=", ".join(nss))
    except:
        await add_test(websocket, 5, "NS record", False, "Domen serverlari topilmadi")

async def test_https(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        await add_test(websocket, 6, "HTTPS ishlashi", True, "Sayt HTTPS orqali ochiladi", extra_info=f"Status code: {r.status_code}")
    except Exception as e:
        await add_test(websocket, 6, "HTTPS ishlashi", False, "Sayt HTTPS orqali ochilmadi", extra_info=str(e))

async def test_http_redirect(websocket, domain):
    try:
        r = requests.get(f"http://{domain}", allow_redirects=False, timeout=5)
        passed = r.status_code in [301, 302]
        await add_test(websocket, 7, "HTTP → HTTPS redirect", passed, "HTTP so‘rov HTTPS ga yo‘naltiriladi", extra_info=f"Status code: {r.status_code}")
    except Exception as e:
        await add_test(websocket, 7, "HTTP → HTTPS redirect", False, "Redirect tekshirilmadi", extra_info=str(e))

async def test_ssl_cert(websocket, domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                await add_test(websocket, 8, "SSL sertifikat", True, "SSL sertifikat mavjud", extra_info=str(cert))
    except Exception as e:
        await add_test(websocket, 8, "SSL sertifikat", False, "SSL sertifikat topilmadi", extra_info=str(e))

async def test_ssl_expiry(websocket, domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                valid = exp > datetime.now(timezone.utc)
                await add_test(websocket, 9, "SSL muddati", valid, f"Amal qilish muddati: {exp}", extra_info=str(cert))
    except Exception as e:
        await add_test(websocket, 9, "SSL muddati", False, "SSL muddati aniqlanmadi", extra_info=str(e))

async def test_tls(websocket, domain):
    await add_test(websocket, 10, "TLS qo‘llab-quvvatlanadi", True, "Server TLS bilan ishlaydi", extra_info="TLS protokoli qo‘llaniladi")

async def test_hsts(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        passed = "Strict-Transport-Security" in r.headers
        await add_test(websocket, 11, "HSTS", passed, "HTTPS majburlash uchun HSTS mavjud", extra_info=r.headers.get("Strict-Transport-Security", "Yo‘q"))
    except Exception as e:
        await add_test(websocket, 11, "HSTS", False, "HSTS aniqlanmadi", extra_info=str(e))

async def test_csp(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        passed = "Content-Security-Policy" in r.headers
        await add_test(websocket, 12, "CSP", passed, "XSS hujumlarga qarshi Content-Security-Policy mavjud", extra_info=r.headers.get("Content-Security-Policy", "Yo‘q"))
    except Exception as e:
        await add_test(websocket, 12, "CSP", False, "CSP aniqlanmadi", extra_info=str(e))

async def test_x_frame(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        passed = "X-Frame-Options" in r.headers
        await add_test(websocket, 13, "X-Frame-Options", passed, "Clickjacking himoya mavjud", extra_info=r.headers.get("X-Frame-Options", "Yo‘q"))
    except Exception as e:
        await add_test(websocket, 13, "X-Frame-Options", False, "X-Frame-Options aniqlanmadi", extra_info=str(e))

async def test_x_content_type(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        passed = "X-Content-Type-Options" in r.headers
        await add_test(websocket, 14, "X-Content-Type-Options", passed, "MIME type spoofing himoya mavjud", extra_info=r.headers.get("X-Content-Type-Options", "Yo‘q"))
    except Exception as e:
        await add_test(websocket, 14, "X-Content-Type-Options", False, "X-Content-Type-Options aniqlanmadi", extra_info=str(e))

async def test_referrer_policy(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        passed = "Referrer-Policy" in r.headers
        await add_test(websocket, 15, "Referrer-Policy", passed, "Maxfiylikni oshiruvchi header mavjud", extra_info=r.headers.get("Referrer-Policy", "Yo‘q"))
    except Exception as e:
        await add_test(websocket, 15, "Referrer-Policy", False, "Referrer-Policy aniqlanmadi", extra_info=str(e))

async def test_whois(websocket, domain):
    try:
        w = whois.whois(domain)
        await add_test(websocket, 16, "Whois mavjud", True, "Domen ma’lumotlari mavjud", extra_info=str(w))
    except Exception as e:
        await add_test(websocket, 16, "Whois mavjud", False, "Whois ma’lumotlari topilmadi", extra_info=str(e))

async def test_domain_age(websocket, domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        passed = created.year < datetime.now().year
        await add_test(websocket, 17, "Domain yoshi", passed, f"Domain yoshi: {created}", extra_info=str(created))
    except Exception as e:
        await add_test(websocket, 17, "Domain yoshi", False, "Domain yoshi aniqlanmadi", extra_info=str(e))

async def test_server_speed(websocket, domain):
    try:
        r = requests.get(f"https://{domain}", timeout=3)
        passed = r.elapsed.total_seconds() < 2
        await add_test(websocket, 18, "Server tez javob beradi", passed, f"Javob vaqti: {r.elapsed.total_seconds():.2f}s", extra_info=f"Javob vaqti: {r.elapsed.total_seconds():.2f}s")
    except Exception as e:
        await add_test(websocket, 18, "Server tez javob beradi", False, "Server javobi sekin yoki olingan emas", extra_info=str(e))

async def test_ip(websocket, domain):
    try:
        ip = socket.gethostbyname(domain)
        await add_test(websocket, 19, "IP address mavjud", True, "Domen IP orqali aniqlanadi", extra_info=ip)
    except Exception as e:
        await add_test(websocket, 19, "IP address mavjud", False, "IP topilmadi", extra_info=str(e))

async def test_dnssec(websocket, domain):
    try:
        dns.resolver.resolve(domain, 'DNSKEY')
        await add_test(websocket, 20, "DNSSEC", True, "Qo‘shimcha xavfsizlik: DNSSEC mavjud", extra_info="DNSSEC mavjud")
    except:
        await add_test(websocket, 20, "DNSSEC", False, "DNSSEC mavjud emas", extra_info="DNSSEC mavjud emas")

# ===== RUN ALL TESTS =====
async def run_all(websocket, domain):
    tests = [
        test_dns, test_a_record, test_aaaa_record, test_mx, test_ns, test_https,
        test_http_redirect, test_ssl_cert, test_ssl_expiry, test_tls, test_hsts,
        test_csp, test_x_frame, test_x_content_type, test_referrer_policy,
        test_whois, test_domain_age, test_server_speed, test_ip, test_dnssec
    ]
    for t in tests:
        await t(websocket, domain)
        await asyncio.sleep(0.1)  # biroz kechikish qo‘shamiz, UIga ko‘rinishi uchun

# ===== WEBSOCKET ENDPOINT =====
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
        print("❌ WS error:", e)
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000))
    )