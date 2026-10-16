"""Бизнес-логика: business logic, pagination, mass assignment, GraphQL."""

from typing import Dict, List

from .base import (
    ScanContext,
    _safe_get,
    _safe_post,
    _body,
    _method_not_supported,
    _is_auth_endpoint,
)
from .descriptions import get_vuln_info


# ================== Business logic (эвристика) ==================
async def check_business_logic(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]

    # Ограничиваем, чтобы не долбить API десятками запросов.
    param_endpoints = param_endpoints[:5]

    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1:ep.find("}")]
        path = ep.replace(f"{{{param_name}}}", "-1")
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None:
            continue
        if r.status_code != 200:
            continue

        try:
            payload = r.json()
        except ValueError:
            continue

        body_lower = _body(r)
        if "error" in body_lower:
            continue

        has_data = False
        if isinstance(payload, dict):
            data = payload.get("data")
            if data not in (None, [], {}, ""):
                has_data = True
            elif data is None:
                extra = {k: v for k, v in payload.items() if k not in ("status", "ok")}
                if extra and any(v not in (None, [], {}, "") for v in extra.values()):
                    has_data = True
        elif isinstance(payload, list):
            has_data = len(payload) > 0

        if has_data:
            findings.append({
                "level": "HIGH",
                "type": "Business Logic Error",
                "endpoint": ep,
                "desc": f"Эвристика: сервер вернул данные для отрицательного {param_name}",
                "details": get_vuln_info("Business Logic Error"),
            })
    return findings


# ================== Pagination ==================
def _count_items(node) -> int:
    """
    Пытается найти количество элементов в типичных обёртках API:
    list, {"data": [...]}, {"items": [...]}, {"results": [...]}, {"rows": [...]}.
    """
    if isinstance(node, list):
        return len(node)
    if isinstance(node, dict):
        for key in ("data", "items", "results", "rows"):
            v = node.get(key)
            if isinstance(v, list):
                return len(v)
    return 0


async def check_pagination(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    static = [e for e in endpoints if "{" not in e and "}" not in e and e.startswith("/")]
    test_path = static[0] if static else "/"
    r = await _safe_get(ctx.client, f"{ctx.target_url}{test_path}?limit=10000")
    if r is None or r.status_code != 200:
        return findings

    try:
        payload = r.json()
    except ValueError:
        # Не JSON — размер body ни о чём не говорит.
        return findings

    count = _count_items(payload)
    if count >= 100:
        findings.append({
            "level": "LOW",
            "type": "Missing Pagination",
            "endpoint": test_path,
            "desc": f"Сервер вернул {count} элементов при limit=10000 — вероятно, пагинация не работает",
            "details": get_vuln_info("Missing Pagination"),
        })
    return findings


# ================== Mass Assignment (эвристика) ==================
async def check_mass_assignment(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []

    # Логин принимает фиксированный набор полей (username/password) —
    # это не «массовое присвоение», а нормальный контракт.
    # Тестировать его на mass-assignment бессмысленно: любой лишний
    # ключ просто игнорируется Pydantic-моделью.
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
        json={"name": "test", "is_admin": True, "role": "admin"},
    )
    if _method_not_supported(r):
        return findings
    if r is None:
        return findings

    if r.status_code in (200, 201):
        findings.append({
            "level": "HIGH",
            "type": "Mass Assignment",
            "endpoint": test_path,
            "desc": "Эвристика: сервер принял лишние поля",
            "details": get_vuln_info("Mass Assignment"),
        })
    return findings


# ================== GraphQL Introspection ==================
async def check_graphql_introspection(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    r = await _safe_post(
        ctx.client, f"{ctx.target_url}/graphql",
        json={"query": "{ __schema { types { name } } }"},
    )
    if r is None:
        return findings
    if r.status_code == 200 and "__schema" in _body(r):
        findings.append({
            "level": "MEDIUM",
            "type": "GraphQL Introspection",
            "endpoint": "/graphql",
            "desc": "Доступна GraphQL интроспекция",
            "details": get_vuln_info("GraphQL Introspection"),
        })
    return findings