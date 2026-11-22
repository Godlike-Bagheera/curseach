"""Прочее: скрытые пути, HTTP без HTTPS, Content-Type, rate limiting."""

import ipaddress
from urllib.parse import urlparse

from .base import (
    ScanContext,
    _is_auth_endpoint,
    _is_html,
    _method_not_supported,
    _norm_body,
    _safe_get,
    _safe_post,
    _writable_endpoints,
)
from .descriptions import get_vuln_info

# ================== Скрытые пути ==================
_HIDDEN_PATHS = [
    "/admin",
    "/backup",
    "/.env",
    "/.git/config",
    "/metrics",
    "/server-status",
    "/actuator",
    "/actuator/env",
    "/api/v2",
    "/swagger.json",
    "/api/swagger",
    "/web.config",
    "/backup.zip",
    "/db.sqlite",
    "/.DS_Store",
    "/phpmyadmin",
    "/wp-admin",
    "/debug/pprof",
    "/elmah.axd",
    "/trace.axd",
]


async def check_hidden_paths(ctx: ScanContext, endpoints: list[str] | None = None) -> list[dict]:
    findings: list = []
    documented = set(endpoints or [])
    spec = ctx.openapi if isinstance(ctx.openapi, dict) else {}
    documented |= set((spec.get("paths") or {}).keys())
    # Baseline несуществующего пути: SPA/catch-all отдаёт тот же 200 на любой URL.
    base = await _safe_get(ctx.client, f"{ctx.target_url}/__nonexistent_baseline_7f3a__")
    base_status = base.status_code if base is not None else None
    base_body = _norm_body(base) if base is not None else ""
    for path in _HIDDEN_PATHS:
        if path in documented:
            continue
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None or r.status_code not in (200, 401, 403):
            continue
        if base_status is not None and r.status_code == base_status and _norm_body(r) == base_body:
            continue
        findings.append(
            {
                "level": "MEDIUM",
                "type": "Hidden Path",
                "endpoint": path,
                "desc": f"Обнаружен незадокументированный путь (HTTP {r.status_code})",
                "details": get_vuln_info("Hidden Path"),
            }
        )
    return findings


# ================== HTTP без HTTPS ==================
def _is_local_or_private_host(host: str) -> bool:
    """Loopback/приватные адреса: HTTP на dev-localhost — не «крик», а замечание."""
    h = (host or "").strip().lower().strip("[]")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


async def check_http_only(ctx: ScanContext, endpoints: list[str] | None = None) -> list[dict]:
    if ctx.target_url.startswith("http://"):
        host = urlparse(ctx.target_url).hostname or ""
        local = _is_local_or_private_host(host)
        return [
            {
                "level": "LOW" if local else "MEDIUM",
                "type": "HTTP without HTTPS",
                "endpoint": "/",
                "desc": (
                    "API использует HTTP без TLS (loopback/приватный хост — риск снижен)"
                    if local
                    else "API использует HTTP, что небезопасно"
                ),
                "details": get_vuln_info("HTTP without HTTPS"),
            }
        ]
    return []


# ================== Content-Type validation (эвристика) ==================
async def check_content_type_validation(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """
    Проверяем, принимает ли сервер данные с неправильным Content-Type.

    FastAPI для json-роутов при text/plain обычно возвращает 422,
    а не 415, поэтому нельзя опираться на '!= 415'. Признак уязвимости —
    сервер реально обработал запрос (2xx).

    Логин пропускаем: он принимает form-data или json по контракту,
    и его проверка на content-type — не про безопасность.
    """
    findings: list = []
    post_endpoints = _writable_endpoints(ctx, endpoints)
    if not post_endpoints:
        return findings

    for test_path in post_endpoints[:3]:
        r = await _safe_post(
            ctx.client,
            f"{ctx.target_url}{test_path}",
            content="test",
            headers={"Content-Type": "text/plain"},
        )
        if r is None or _method_not_supported(r):
            continue
        if r.status_code in (200, 201, 202):
            findings.append(
                {
                    "level": "LOW",
                    "type": "Missing Content-Type Validation",
                    "endpoint": test_path,
                    "desc": "Сервер принял неподдерживаемый Content-Type и обработал данные",
                    "details": get_vuln_info("Missing Content-Type Validation"),
                }
            )
        return findings
    return findings


# ================== Rate Limiting ==================
_RATELIMIT_PROBE_PATHS = {"/.env", "/.git/config", "/.DS_Store", "/web.config", "/backup.zip", "/db.sqlite", "/backup"}


async def check_rate_limiting(ctx: ScanContext, endpoints: list[str] | None = None) -> list[dict]:
    """Rate-limit оцениваем на API/auth-маршруте, а не на статике/SPA-fallback."""
    findings: list = []
    eps = endpoints or []
    candidates = [e for e in eps if "{" not in e and "}" not in e and e not in _RATELIMIT_PROBE_PATHS]
    auth_eps = [e for e in candidates if _is_auth_endpoint(e)]
    api_eps = [e for e in candidates if e.lower().startswith("/api/")]
    pool = auth_eps or api_eps
    if not pool:
        return findings  # rate-limit осмысленен на API/auth-маршрутах, не на голом корне/статике
    test_path = pool[0]
    url = f"{ctx.target_url}{test_path}"

    base = await _safe_get(ctx.client, f"{ctx.target_url}/__nonexistent_baseline_rl__")
    r0 = await _safe_get(ctx.client, url)
    if r0 is None:
        return findings
    if base is not None and r0.status_code == base.status_code and _norm_body(r0) == _norm_body(base) and _is_html(r0):
        return findings

    NUM_REQUESTS = 50
    statuses = []
    got_429 = False
    for _ in range(NUM_REQUESTS):
        r = await _safe_get(ctx.client, url)
        if r is None:
            continue
        statuses.append(r.status_code)
        if r.status_code == 429:
            got_429 = True
            break

    if got_429:
        return findings

    # Равномерные non-200 (все 404) — не признак отсутствия rate-limit.
    if statuses and len(set(statuses)) == 1 and statuses[0] == 200:
        findings.append(
            {
                "level": "LOW",
                "type": "Lack of Rate Limiting",
                "endpoint": test_path,
                "desc": f"{NUM_REQUESTS} запросов подряд не вызвали блокировку (429)",
                "details": get_vuln_info("Lack of Rate Limiting"),
            }
        )
    return findings


async def check_security_txt(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """security.txt (RFC 9116): опубликованы ли контакты для сообщения об уязвимостях."""
    findings: list = []
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is not None and r.status_code == 200 and "contact:" in (r.text or "").lower():
            return findings
    findings.append(
        {
            "level": "LOW",
            "type": "Missing security.txt",
            "endpoint": "/.well-known/security.txt",
            "desc": "Нет security.txt (RFC 9116) — контакты для сообщения об уязвимостях не опубликованы",
            "details": get_vuln_info("Missing security.txt"),
        }
    )
    return findings
