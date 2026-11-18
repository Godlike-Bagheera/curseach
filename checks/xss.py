"""Отражённый XSS: path/query/body-параметры, все методы из OpenAPI."""

import asyncio
from typing import Dict, List

from .base import ScanContext, ev
from .descriptions import get_vuln_info
from .surface import Surface, build_surfaces, probe

_XSS_PAYLOADS = [
    ("<script>alert(1)</script>",      "HTML-контекст"),
    ("\"><script>alert(1)</script>",   "атрибут (двойные кавычки)"),
    ("'><script>alert(1)</script>",    "атрибут (одинарные кавычки)"),
    ("<img src=x onerror=alert(1)>",   "обработчик события"),
    ("<svg/onload=alert(1)>",          "SVG-контекст"),
]


async def check_xss(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    surfaces = build_surfaces(ctx, endpoints)

    async def per_surface(s: Surface) -> List[Dict]:
        for kind, name in s.injectable:
            for payload, ctx_label in _XSS_PAYLOADS:
                if kind == "path":
                    r = await probe(ctx, s, path_over={name: payload})
                elif kind == "query":
                    r = await probe(ctx, s, query_over={name: payload})
                else:
                    r = await probe(ctx, s, body_over={name: payload})
                if r is None:
                    continue
                # Отражение в JSON/тексте — не XSS: браузер не исполнит скрипт
                # из application/json. Флагаем только HTML-ответы.
                ctype = r.headers.get("content-type", "").lower()
                if "text/html" not in ctype and "application/xhtml" not in ctype:
                    continue
                try:
                    body = r.text
                except (UnicodeDecodeError, LookupError):
                    continue
                if payload in body:
                    return [{
                        "level": "MEDIUM",
                        "type": "Reflected XSS",
                        "endpoint": s.path,
                        "method": s.method.upper(),
                        "param": f"{kind}:{name}",
                        "desc": f"{kind}-параметр {name} отражает payload без экранирования ({ctx_label})",
                        "details": get_vuln_info("Reflected XSS"),
                        "confidence": "high",
                        "evidence": ev(r),
                    }]
        return []

    results = await asyncio.gather(*(per_surface(s) for s in surfaces))
    return [f for chunk in results for f in chunk]
