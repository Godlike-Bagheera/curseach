"""Заголовки безопасности, TLS/сертификат, опасные HTTP-методы."""

import asyncio
import datetime
import socket
import ssl
from urllib.parse import urlparse

from .base import ScanContext, _safe_get, _safe_options
from .descriptions import get_vuln_info


async def check_security_headers(ctx: ScanContext, endpoints: list[str] | None = None) -> list[dict]:
    findings: list = []
    # X-XSS-Protection намеренно НЕ проверяем: заголовок устарел (OWASP: 0 или не ставить).
    required = {
        "x-frame-options": ("Отсутствует X-Frame-Options", "Missing Security Headers"),
        "x-content-type-options": ("Отсутствует X-Content-Type-Options", "Missing Security Headers"),
        "content-security-policy": ("Отсутствует Content-Security-Policy", "Missing CSP"),
        "strict-transport-security": ("Отсутствует Strict-Transport-Security", "Missing HSTS"),
    }
    r = await _safe_get(ctx.client, ctx.target_url)
    if r is None:
        return findings
    for hdr, (msg, vuln_type) in required.items():
        if hdr not in r.headers:
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": vuln_type,
                    "endpoint": "/",
                    "desc": msg,
                    "details": get_vuln_info(vuln_type),
                }
            )
    return findings


def _tls_probe(host: str, port: int) -> dict:
    """Синхронный TLS-хендшейк: версия протокола + валидность/срок сертификата."""
    out: dict[str, object] = {}
    try:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with c.wrap_socket(sock, server_hostname=host) as tls:
                out["version"] = tls.version()
    except (OSError, ssl.SSLError):
        return out
    try:
        c = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with c.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        not_after = (cert or {}).get("notAfter")
        if isinstance(not_after, str):
            out["expires_ts"] = ssl.cert_time_to_seconds(not_after)
        out["trusted"] = True
    except ssl.SSLCertVerificationError:
        out["trusted"] = False
    except (OSError, ssl.SSLError):
        pass
    return out


async def check_tls_version(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """Реальная проверка TLS (протокол + сертификат), а не дубль HSTS."""
    findings: list = []
    if not ctx.target_url.startswith("https://"):
        return findings
    parsed = urlparse(ctx.target_url)
    host = parsed.hostname
    if not host:
        return findings
    info = await asyncio.to_thread(_tls_probe, host, parsed.port or 443)
    if not info:
        return findings
    version = info.get("version")
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(
            {
                "level": "HIGH",
                "type": "Weak TLS Version",
                "endpoint": "/",
                "desc": f"Сервер согласовал устаревший протокол {version}",
                "details": get_vuln_info("Weak TLS Version"),
            }
        )
    if info.get("trusted") is False:
        findings.append(
            {
                "level": "MEDIUM",
                "type": "TLS Certificate Untrusted",
                "endpoint": "/",
                "desc": "Сертификат не прошёл валидацию (самоподписанный / не тот хост / битая цепочка)",
                "details": get_vuln_info("TLS Certificate Untrusted"),
            }
        )
    expires_ts = info.get("expires_ts")
    if expires_ts:
        days_left = (expires_ts - datetime.datetime.now(datetime.timezone.utc).timestamp()) / 86400
        if days_left < 0:
            findings.append(
                {
                    "level": "HIGH",
                    "type": "TLS Certificate Expired",
                    "endpoint": "/",
                    "desc": "Срок действия TLS-сертификата истёк",
                    "details": get_vuln_info("TLS Certificate Expired"),
                }
            )
        elif days_left < 14:
            findings.append(
                {
                    "level": "LOW",
                    "type": "TLS Certificate Expiring Soon",
                    "endpoint": "/",
                    "desc": f"TLS-сертификат истекает через {int(days_left)} дн.",
                    "details": get_vuln_info("TLS Certificate Expiring Soon"),
                }
            )
    return findings


async def check_unsafe_methods(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    test_path = endpoints[0] if endpoints else "/"
    r = await _safe_options(ctx.client, f"{ctx.target_url}{test_path}")
    if r is None:
        return findings
    allow = r.headers.get("allow", "")
    if allow:
        methods = [m.strip().upper() for m in allow.split(",")]
        dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE")]
        if dangerous:
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": "Unsafe HTTP Methods",
                    "endpoint": test_path,
                    "desc": f"Разрешены опасные методы: {', '.join(dangerous)}",
                    "details": get_vuln_info("Unsafe HTTP Methods"),
                }
            )
    return findings
