"""Отражённый XSS."""

from typing import Dict, List

from .base import ScanContext, _safe_get, _build_path
from .descriptions import get_vuln_info


_XSS_PAYLOADS = [
    ("<script>alert(1)</script>",      "HTML-контекст"),
    ("\"><script>alert(1)</script>",   "атрибут (двойные кавычки)"),
    ("'><script>alert(1)</script>",    "атрибут (одинарные кавычки)"),
    ("<img src=x onerror=alert(1)>",   "обработчик события"),
    ("<svg/onload=alert(1)>",          "SVG-контекст"),
]


async def check_xss(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]

    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1:ep.find("}")]
        for payload, ctx_label in _XSS_PAYLOADS:
            path = _build_path(ep, param_name, payload)
            r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
            if r is None:
                continue
            try:
                body = r.text
            except (UnicodeDecodeError, LookupError):
                continue

            if payload in body:
                findings.append({
                    "level": "MEDIUM",
                    "type": "Reflected XSS",
                    "endpoint": ep,
                    "desc": f"Параметр {param_name} отражает payload без экранирования ({ctx_label})",
                    "details": get_vuln_info("Reflected XSS"),
                })
                break
    return findings