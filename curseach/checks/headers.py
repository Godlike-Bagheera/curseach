"""Заголовки безопасности, версия TLS, опасные HTTP-методы."""

from typing import Dict, List, Optional

from .base import ScanContext, _safe_get, _safe_options
from .descriptions import get_vuln_info


# ================== Security Headers ==================
async def check_security_headers(
    ctx: ScanContext, endpoints: Optional[List[str]] = None
) -> List[Dict]:
    findings = []
    required = {
        "x-frame-options":           ("Отсутствует X-Frame-Options",           "Missing Security Headers"),
        "x-content-type-options":    ("Отсутствует X-Content-Type-Options",    "Missing Security Headers"),
        "x-xss-protection":          ("Отсутствует X-XSS-Protection",          "Missing Security Headers"),
        "content-security-policy":   ("Отсутствует Content-Security-Policy",   "Missing CSP"),
        "strict-transport-security": ("Отсутствует Strict-Transport-Security", "Missing HSTS"),
    }
    r = await _safe_get(ctx.client, ctx.target_url)
    if r is None:
        return findings
    for hdr, (msg, vuln_type) in required.items():
        if hdr not in r.headers:
            findings.append({
                "level": "MEDIUM",
                "type": vuln_type,
                "endpoint": "/",
                "desc": msg,
                "details": get_vuln_info(vuln_type),
            })
    return findings


# ================== TLS version ==================
async def check_tls_version(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    if not ctx.target_url.startswith("https://"):
        return findings
    r = await _safe_get(ctx.client, ctx.target_url)
    if r is None:
        return findings
    if "strict-transport-security" not in r.headers:
        findings.append({
            "level": "MEDIUM",
            "type": "Weak TLS Version",
            "endpoint": "/",
            "desc": "Отсутствует HSTS",
            "details": get_vuln_info("Weak TLS Version"),
        })
    return findings


# ================== Unsafe HTTP methods ==================
async def check_unsafe_methods(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    test_path = endpoints[0] if endpoints else "/"
    r = await _safe_options(ctx.client, f"{ctx.target_url}{test_path}")
    if r is None:
        return findings
    allow = r.headers.get("allow", "")
    if allow:
        methods = [m.strip().upper() for m in allow.split(",")]
        dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE")]
        if dangerous:
            findings.append({
                "level": "MEDIUM",
                "type": "Unsafe HTTP Methods",
                "endpoint": test_path,
                "desc": f"Разрешены опасные методы: {', '.join(dangerous)}",
                "details": get_vuln_info("Unsafe HTTP Methods"),
            })
    return findings