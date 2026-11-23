"""Отражённый XSS: path/query/body-параметры, все методы из OpenAPI."""

import asyncio

from .base import ScanContext, _safe_get, _safe_post, _writable_endpoints, ev
from .descriptions import get_vuln_info
from .surface import Surface, build_surfaces, probe

_XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "HTML-контекст"),
    ('"><script>alert(1)</script>', "атрибут (двойные кавычки)"),
    ("'><script>alert(1)</script>", "атрибут (одинарные кавычки)"),
    ("<img src=x onerror=alert(1)>", "обработчик события"),
    ("<svg/onload=alert(1)>", "SVG-контекст"),
]


async def check_xss(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    surfaces = build_surfaces(ctx, endpoints)

    async def per_surface(s: Surface) -> list[dict]:
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
                    return [
                        {
                            "level": "MEDIUM",
                            "type": "Reflected XSS",
                            "endpoint": s.path,
                            "method": s.method.upper(),
                            "param": f"{kind}:{name}",
                            "desc": f"{kind}-параметр {name} отражает payload без экранирования ({ctx_label})",
                            "details": get_vuln_info("Reflected XSS"),
                            "confidence": "high",
                            "evidence": ev(r),
                        }
                    ]
        return []

    results = await asyncio.gather(*(per_surface(s) for s in surfaces))
    return [f for chunk in results for f in chunk]


async def check_stored_xss(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """POST с XSS-payload в writable-эндпоинты, затем GET HTML-страниц: ищем неотэкранированное отражение."""
    findings: list[dict] = []
    payload = "<script>alert(1337)</script>"
    for ep in _writable_endpoints(ctx, endpoints)[:3]:
        await _safe_post(
            ctx.client,
            f"{ctx.target_url}{ep}",
            json={"comment": payload, "text": payload, "body": payload, "name": payload, "message": payload},
        )
    static = [e for e in endpoints if "{" not in e and "}" not in e]
    for ep in static[:12]:
        r = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        if r is None:
            continue
        try:
            text = r.text
        except (UnicodeDecodeError, LookupError):
            continue
        if "html" in r.headers.get("content-type", "") and payload in text:
            findings.append(
                {
                    "level": "HIGH",
                    "type": "Stored XSS",
                    "endpoint": ep,
                    "method": "GET",
                    "desc": "Payload из POST отражается без экранирования в HTML — хранимый XSS",
                    "confidence": "high",
                    "details": get_vuln_info("Stored XSS"),
                    "evidence": ev(r),
                }
            )
            break
    return findings
