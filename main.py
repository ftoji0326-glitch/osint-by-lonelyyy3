# узел: meridian/recon/main_backend
# python_version: >=3.10
# deps: fastapi==0.110.0, uvicorn==0.28.0, dnspython==2.6.1, httpx==0.27.0
# запуск: pip install fastapi uvicorn dnspython httpx
#         python main.py

import asyncio
import os
import re
import socket
import ssl
from typing import Any, Dict, List, Set
import dns.resolver
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="G.U.N OSINT Station Engine", version="2.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE_PATH = os.path.join(BASE_DIR, "index.html")

def sanitize_domain(target: str) -> str:
    cleaned = target.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split(":")[0]
    return cleaned

async def resolve_dns_records(domain: str) -> Dict[str, List[str]]:
    loop = asyncio.get_running_loop()
    results: Dict[str, List[str]] = {}

    def _sync_dns_query(record_type: str) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(domain, record_type)
            return [rdata.to_text() for rdata in answers]
        except Exception:
            return []

    types_to_check = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    for r_type in types_to_check:
        records = await loop.run_in_executor(None, _sync_dns_query, r_type)
        if records:
            results[r_type] = records

    return results

async def retrieve_tls_certificate(domain: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()

    def _inspect_socket() -> Dict[str, Any]:
        context = ssl.create_default_context()
        context.timeout = 4.0
        try:
            with socket.create_connection((domain, 443), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"error": "Пустой сертификат узла"}

                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    alt_names = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

                    return {
                        "common_name": subject.get("commonName", "—"),
                        "issuer": issuer.get("organizationName", issuer.get("commonName", "Не указан")),
                        "valid_from": cert.get("notBefore"),
                        "valid_to": cert.get("notAfter"),
                        "version": cert.get("version"),
                        "subject_alt_names": alt_names[:10]
                    }
        except Exception as e:
            return {"error": f"Сбой TLS: {str(e)}"}

    return await loop.run_in_executor(None, _inspect_socket)

async def probe_http_surface(domain: str) -> Dict[str, Any]:
    url = f"https://{domain}"
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=5.0) as client:
        try:
            response = await client.get(url)
            headers = dict(response.headers)
            sec_headers = {
                "Strict-Transport-Security": headers.get("strict-transport-security", "ОТСУТСТВУЕТ"),
                "Content-Security-Policy": headers.get("content-security-policy", "ОТСУТСТВУЕТ"),
                "X-Frame-Options": headers.get("x-frame-options", "ОТСУТСТВУЕТ"),
                "X-Content-Type-Options": headers.get("x-content-type-options", "ОТСУТСТВУЕТ"),
                "Referrer-Policy": headers.get("referrer-policy", "ОТСУТСТВУЕТ"),
            }
            return {
                "status_code": response.status_code,
                "server": headers.get("server", "Скрыт"),
                "security_headers": sec_headers
            }
        except Exception as e:
            return {
                "status_code": None,
                "server": "Недоступен",
                "error": str(e),
                "security_headers": {}
            }

async def fetch_ip_telemetry(ip_or_domain: str) -> Dict[str, Any]:
    url = f"http://ip-api.com/json/{ip_or_domain}?fields=status,message,country,city,as,query"
    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    return data
            return {"query": ip_or_domain, "country": "Неизвестно", "as": "Неизвестно"}
        except Exception:
            return {"query": ip_or_domain, "country": "Сбой шлюза", "as": "Сбой шлюза"}

async def enumerate_subdomains(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with httpx.AsyncClient(timeout=6.0) as client:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            data = resp.json()
            found: Set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if "*" not in sub and sub.endswith(domain) and sub != domain:
                        found.add(sub)
            return sorted(list(found))[:50]
        except Exception:
            return []

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    if not os.path.exists(INDEX_FILE_PATH):
        raise HTTPException(status_code=404, detail="Интерфейсный файл index.html не найден на узле")
    with open(INDEX_FILE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.get("/api/scan")
async def execute_osint_scan(target: str):
    clean_target = sanitize_domain(target)
    if not clean_target:
        raise HTTPException(status_code=400, detail="Целевой домен не передан")

    dns_task = resolve_dns_records(clean_target)
    ssl_task = retrieve_tls_certificate(clean_target)
    http_task = probe_http_surface(clean_target)
    geo_task = fetch_ip_telemetry(clean_target)
    sub_task = enumerate_subdomains(clean_target)

    dns_res, ssl_res, http_res, geo_res, sub_res = await asyncio.gather(
        dns_task, ssl_task, http_task, geo_task, sub_task, return_exceptions=False
    )

    return {
        "target": clean_target,
        "dns": dns_res,
        "ssl": ssl_res,
        "http": http_res,
        "geo": geo_res,
        "subdomains": sub_res
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)