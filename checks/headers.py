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
    is_https = ctx.target_url.startswith("https://")
    for hdr, (msg, vuln_type) in required.items():
        # HSTS имеет смысл только поверх HTTPS (на http это шум).
        if hdr == "strict-transport-security" and not is_https:
            continue
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
    csp = r.headers.get("content-security-policy", "")
    if csp:
        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            toks = part.strip().split()
            if toks:
                directives[toks[0].lower()] = [t.lower() for t in toks[1:]]
        script_src = directives.get("script-src", directives.get("default-src", []))
        weak = [t for t in script_src if t in ("'unsafe-inline'", "'unsafe-eval'", "*")]
        if weak:
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": "Weak CSP",
                    "endpoint": "/",
                    "desc": "CSP ослаблен в script-src/default-src: " + ", ".join(weak),
                    "details": get_vuln_info("Weak CSP"),
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
    except ssl.SSLCertVerificationError as exc:
        out["trusted"] = False
        # Истёкший сертификат не проходит verified-handshake → notAfter недоступен.
        # Классифицируем по сообщению OpenSSL, иначе «Expired» не срабатывал бы.
        msg = f"{getattr(exc, 'verify_message', '')} {exc}".lower()
        if "expired" in msg or "not yet valid" in msg:
            out["expired"] = True
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
        if info.get("expired"):
            findings.append(
                {
                    "level": "HIGH",
                    "type": "TLS Certificate Expired",
                    "endpoint": "/",
                    "desc": "Срок действия TLS-сертификата истёк (сертификат не прошёл валидацию)",
                    "details": get_vuln_info("TLS Certificate Expired"),
                }
            )
        else:
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
        # PUT/DELETE — норма для REST. Опасны TRACE/TRACK (XST), CONNECT и WebDAV.
        dangerous = [
            m
            for m in methods
            if m in ("TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")
        ]
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
