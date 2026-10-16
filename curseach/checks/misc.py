"""Прочее: скрытые пути, HTTP без HTTPS, Content-Type, rate limiting."""

from typing import Dict, List, Optional

from .base import (
    ScanContext,
    _safe_get,
    _safe_post,
    _method_not_supported,
    _is_auth_endpoint,
)
from .descriptions import get_vuln_info


# ================== Скрытые пути ==================
async def check_hidden_paths(
    ctx: ScanContext, endpoints: Optional[List[str]] = None
) -> List[Dict]:
    findings = []
    hidden_paths = [
        "/admin", "/backup", "/.env", "/metrics",
        "/api/v2", "/swagger.json", "/api/swagger",
    ]
    for path in hidden_paths:
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None:
            continue
        if r.status_code in (200, 401, 403):
            findings.append({
                "level": "MEDIUM",
                "type": "Hidden Path",
                "endpoint": path,
                "desc": f"Обнаружен незадокументированный путь (HTTP {r.status_code})",
                "details": get_vuln_info("Hidden Path"),
            })
    return findings


# ================== HTTP без HTTPS ==================
async def check_http_only(
    ctx: ScanContext, endpoints: Optional[List[str]] = None
) -> List[Dict]:
    if ctx.target_url.startswith("http://"):
        return [{
            "level": "MEDIUM",
            "type": "HTTP without HTTPS",
            "endpoint": "/",
            "desc": "API использует HTTP, что небезопасно",
            "details": get_vuln_info("HTTP without HTTPS"),
        }]
    return []


# ================== Content-Type validation (эвристика) ==================
async def check_content_type_validation(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    """
    Проверяем, принимает ли сервер данные с неправильным Content-Type.

    FastAPI для json-роутов при text/plain обычно возвращает 422,
    а не 415, поэтому нельзя опираться на '!= 415'. Признак уязвимости —
    сервер реально обработал запрос (2xx).

    Логин пропускаем: он принимает form-data или json по контракту,
    и его проверка на content-type — не про безопасность.
    """
    findings = []
    post_endpoints = [
        e for e in endpoints
        if "{" not in e and "}" not in e
        and e.startswith("/")
        and not _is_auth_endpoint(e)
    ]
    if not post_endpoints:
        return findings

    test_path = post_endpoints[0]
    r = await _safe_post(
        ctx.client, f"{ctx.target_url}{test_path}",
        content="test", headers={"Content-Type": "text/plain"},
    )
    if _method_not_supported(r):
        return findings
    if r is None:
        return findings

    if r.status_code in (200, 201, 202):
        findings.append({
            "level": "LOW",
            "type": "Missing Content-Type Validation",
            "endpoint": test_path,
            "desc": "Сервер принял неподдерживаемый Content-Type и обработал данные",
            "details": get_vuln_info("Missing Content-Type Validation"),
        })
    return findings


# ================== Rate Limiting ==================
async def check_rate_limiting(
    ctx: ScanContext, endpoints: Optional[List[str]] = None
) -> List[Dict]:
    findings = []
    test_path = "/"
    if endpoints:
        static = [e for e in endpoints if "{" not in e and "}" not in e]
        if static:
            test_path = static[0]
    url = f"{ctx.target_url}{test_path}"

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

    if statuses and len(set(statuses)) == 1:
        findings.append({
            "level": "LOW",
            "type": "Lack of Rate Limiting",
            "endpoint": test_path,
            "desc": f"{NUM_REQUESTS} запросов подряд не вызвали блокировку (429)",
            "details": get_vuln_info("Lack of Rate Limiting"),
        })
    return findings