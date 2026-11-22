"""Discovery эндпоинтов без OpenAPI-спеки: robots.txt, sitemap.xml, common-paths."""

import re

from .base import ScanContext, _norm_body, _safe_get

_COMMON_PATHS = [
    "/admin",
    "/api",
    "/api/v1",
    "/graphql",
    "/health",
    "/healthz",
    "/metrics",
    "/swagger.json",
    "/docs",
    "/login",
    "/api/users",
    "/api/products",
    "/status",
    "/version",
    "/debug",
    "/config",
    "/.env",
    "/server-status",
]


def _path_from_url(val: str) -> str | None:
    if val.startswith("/"):
        return val.split("?", 1)[0].rstrip("/") or "/"
    if "://" in val:
        rest = val.split("://", 1)[1]
        path = rest[rest.find("/") :] if "/" in rest else "/"
        return path.split("?", 1)[0].rstrip("/") or "/"
    return None


async def discover_endpoints(ctx: ScanContext) -> list[str]:
    """Когда спеки нет: собираем пути из robots.txt/sitemap.xml и пробуем частые адреса."""
    found: set = set()
    r = await _safe_get(ctx.client, f"{ctx.target_url}/robots.txt")
    if r is not None and r.status_code == 200:
        for line in r.text.splitlines():
            m = re.match(r"(?i)^\s*(?:disallow|allow|sitemap):\s*(\S+)", line)
            if m:
                p = _path_from_url(m.group(1))
                if p:
                    found.add(p)
    r = await _safe_get(ctx.client, f"{ctx.target_url}/sitemap.xml")
    if r is not None and r.status_code == 200:
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text):
            p = _path_from_url(loc)
            if p:
                found.add(p)
    base = await _safe_get(ctx.client, f"{ctx.target_url}/__nonexistent_baseline_disc__")
    base_status = base.status_code if base is not None else None
    base_body = _norm_body(base) if base is not None else None
    for p in _COMMON_PATHS:
        rr = await _safe_get(ctx.client, f"{ctx.target_url}{p}")
        if rr is None or rr.status_code in (404, 410):
            continue
        if base_body is not None and rr.status_code == base_status and _norm_body(rr) == base_body:
            continue
        found.add(p)
    return sorted(found)
