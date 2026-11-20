"""SSRF: сервер сам ходит по URL, который подсунул клиент.

Проверка ищет URL-подобные параметры (url/link/webhook/image/…) и подставляет
адреса облачных метаданных (169.254.169.254) и внутренних сервисов (127.0.0.1).
Если в ответе появляются маркеры внутренних данных — сервер сходил по адресу
клиента (SSRF). Blind-SSRF без ответа содержимого требует OOB-канала и здесь
не детектируется.
"""

import asyncio

from .base import ScanContext, _body, ev
from .descriptions import get_vuln_info
from .surface import Surface, build_surfaces, probe

_VTYPE = "Server-Side Request Forgery"

_URL_MARKERS = (
    "url", "uri", "link", "href", "src", "endpoint", "webhook", "callback",
    "image", "avatar", "photo", "logo", "feed", "site", "host", "domain",
    "fetch", "proxy", "redirect", "next", "target", "dest", "remote",
    "resource", "load", "download", "import", "address", "addr",
)
_METADATA_PAYLOADS = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[fd00:ec2::254]/latest/meta-data/",
)
_METADATA_SIGS = ("ami-id", "instance-id", "security-credentials", "accesskeyid", "computemetadata", "instance-identity")
_INTERNAL_PAYLOADS = ("http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/")
_INTERNAL_SIGS = ("internal-admin-panel", "internal-service", "server-status", "phpinfo()", "actuator/env", "manager/html")


def _url_like(name: str) -> bool:
    n = name.lower()
    return any(m in n for m in _URL_MARKERS)


def _mk(s: Surface, kind: str, name: str, desc: str, evidence: dict | None, confidence: str) -> dict:
    return {
        "level": "HIGH",
        "type": _VTYPE,
        "endpoint": s.path,
        "method": s.method.upper(),
        "param": f"{kind}:{name}",
        "desc": desc,
        "details": get_vuln_info(_VTYPE),
        "confidence": confidence,
        "evidence": evidence,
    }


async def _probe_param(ctx: ScanContext, s: Surface, kind: str, name: str, value: str):
    if kind == "path":
        return await probe(ctx, s, path_over={name: value})
    if kind == "query":
        return await probe(ctx, s, query_over={name: value})
    return await probe(ctx, s, body_over={name: value})


async def _test_param(ctx: ScanContext, s: Surface, kind: str, name: str) -> dict | None:
    base = await _probe_param(ctx, s, kind, name, "http://example.com/")
    base_body = _body(base)
    for payload in _METADATA_PAYLOADS:
        r = await _probe_param(ctx, s, kind, name, payload)
        if r is None:
            continue
        b = _body(r)
        hit = next((sig for sig in _METADATA_SIGS if sig in b and sig not in base_body), None)
        if hit:
            return _mk(
                s, kind, name,
                f"SSRF: {kind}-параметр {name} — сервер вернул метаданные облака (payload {payload}, маркер {hit})",
                ev(r), "high",
            )
    for payload in _INTERNAL_PAYLOADS:
        r = await _probe_param(ctx, s, kind, name, payload)
        if r is None:
            continue
        b = _body(r)
        hit = next((sig for sig in _INTERNAL_SIGS if sig in b and sig not in base_body), None)
        if hit:
            return _mk(
                s, kind, name,
                f"SSRF: {kind}-параметр {name} — сервер вернул содержимое внутреннего сервиса (payload {payload}, маркер {hit})",
                ev(r), "medium",
            )
    return None


async def check_ssrf(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    surfaces = build_surfaces(ctx, endpoints)

    async def per_surface(s: Surface) -> list[dict]:
        out = []
        for kind, name in s.injectable:
            if not _url_like(name):
                continue
            f = await _test_param(ctx, s, kind, name)
            if f:
                out.append(f)
        return out

    results = await asyncio.gather(*(per_surface(s) for s in surfaces))
    return [f for chunk in results for f in chunk]
