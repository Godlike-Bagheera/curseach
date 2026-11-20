"""Path Traversal / LFI и открытый редирект — инъекции в параметры запроса."""

from .base import ScanContext, _body, _is_auth_endpoint, ev
from .descriptions import get_vuln_info
from .surface import build_surfaces, probe

_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
]
_TRAVERSAL_SIGS = ["root:x:0:0", "root:*:0:0", "[boot loader]", "; for 16-bit app support", "/bin/bash", "/bin/sh"]
_FILE_PARAMS = {"file", "path", "page", "doc", "document", "folder", "dir", "include", "template", "load", "read", "download", "filename", "filepath", "name", "f"}


async def check_path_traversal(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """Пробуем path-параметры/query/тело traversal-payload'ами и ищем сигнатуры системных файлов."""
    findings: list[dict] = []
    seen: set = set()
    for s in build_surfaces(ctx, endpoints)[:12]:
        if _is_auth_endpoint(s.path):
            continue
        for kind, name in s.injectable:
            if (s.path, name) in seen:
                continue
            # приоритет «файловым» параметрам, но пробуем и остальные
            for payload in _TRAVERSAL_PAYLOADS:
                over = {name: payload}
                r = await probe(
                    ctx,
                    s,
                    path_over=over if kind == "path" else None,
                    query_over=over if kind == "query" else None,
                    body_over=over if kind == "body" else None,
                )
                if r is None or r.status_code >= 500:
                    continue
                body = _body(r)
                if any(sig in body for sig in _TRAVERSAL_SIGS):
                    seen.add((s.path, name))
                    findings.append(
                        {
                            "level": "HIGH",
                            "type": "Path Traversal",
                            "endpoint": s.path,
                            "method": s.method.upper(),
                            "param": name,
                            "desc": f"Path traversal в параметре «{name}»: ответ содержит сигнатуру системного файла",
                            "confidence": "high",
                            "details": get_vuln_info("Path Traversal"),
                            "evidence": ev(r),
                        }
                    )
                    break
    return findings


_REDIRECT_PARAMS = {"redirect", "next", "url", "return", "returnurl", "return_url", "redirect_uri", "redirect_url", "go", "target", "dest", "destination", "forward", "continue", "rurl"}
_EVIL = "https://evil.example/"


async def check_open_redirect(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """Параметры redirect/next/url… с внешним адресом: смотрим Location у 3xx и meta-refresh в 200."""
    findings: list[dict] = []
    seen: set = set()
    for s in build_surfaces(ctx, endpoints)[:15]:
        for kind, name in s.injectable:
            if name.lower() not in _REDIRECT_PARAMS or (s.path, name) in seen:
                continue
            over = {name: _EVIL}
            r = await probe(
                ctx,
                s,
                path_over=over if kind == "path" else None,
                query_over=over if kind == "query" else None,
                body_over=over if kind == "body" else None,
            )
            if r is None:
                continue
            loc = r.headers.get("location", "")
            body = _body(r)
            hit = (300 <= r.status_code < 400 and loc.startswith(_EVIL)) or (
                r.status_code == 200 and "evil.example" in body and ("url=https://evil.example" in body or "window.location" in body or "http-equiv" in body)
            )
            if hit:
                seen.add((s.path, name))
                findings.append(
                    {
                        "level": "MEDIUM",
                        "type": "Open Redirect",
                        "endpoint": s.path,
                        "method": s.method.upper(),
                        "param": name,
                        "desc": f"Открытый редирект: параметр «{name}» уводит на произвольный внешний адрес",
                        "confidence": "high",
                        "details": get_vuln_info("Open Redirect"),
                        "evidence": ev(r),
                    }
                )
    return findings
