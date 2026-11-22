"""Бизнес-логика: business logic, pagination, mass assignment, GraphQL."""

from .base import (
    ScanContext,
    _body,
    _method_not_supported,
    _safe_get,
    _safe_post,
    _writable_endpoints,
)
from .descriptions import get_vuln_info


# ================== Business logic (эвристика) ==================
async def check_business_logic(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]

    # Ограничиваем, чтобы не долбить API десятками запросов.
    param_endpoints = param_endpoints[:5]

    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1 : ep.find("}")]
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
            findings.append(
                {
                    "level": "HIGH",
                    "type": "Business Logic Error",
                    "endpoint": ep,
                    "desc": f"Эвристика: сервер вернул данные для отрицательного {param_name}",
                    "details": get_vuln_info("Business Logic Error"),
                }
            )
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


_COLLECTION_MARKERS = (
    "items",
    "products",
    "orders",
    "users",
    "records",
    "list",
    "collection",
    "entries",
    "goods",
    "catalog",
)
_NON_COLLECTION = {"/", "/docs", "/redoc", "/openapi.json", "/health", "/healthz", "/robots.txt", "/favicon.ico"}


async def check_pagination(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    static = [e for e in endpoints if "{" not in e and "}" not in e and e.startswith("/")]
    candidates = [e for e in static if any(k in e.lower() for k in _COLLECTION_MARKERS)]
    if not candidates:
        candidates = [e for e in static if e not in _NON_COLLECTION]
    for test_path in candidates[:5]:
        r = await _safe_get(ctx.client, f"{ctx.target_url}{test_path}?limit=10000")
        if r is None or r.status_code != 200:
            continue
        try:
            payload = r.json()
        except ValueError:
            continue
        count = _count_items(payload)
        if count >= 100:
            findings.append(
                {
                    "level": "LOW",
                    "type": "Missing Pagination",
                    "endpoint": test_path,
                    "desc": f"Сервер вернул {count} элементов при limit=10000 — вероятно, пагинация не работает",
                    "details": get_vuln_info("Missing Pagination"),
                }
            )
            break
    return findings


# ================== Mass Assignment (эвристика) ==================
async def check_mass_assignment(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    # Логин принимает фиксированный набор полей (username/password) —
    # это не «массовое присвоение», а нормальный контракт.
    # Тестировать его на mass-assignment бессмысленно: любой лишний
    # ключ просто игнорируется Pydantic-моделью.
    post_endpoints = _writable_endpoints(ctx, endpoints)
    if not post_endpoints:
        return findings

    for test_path in post_endpoints[:3]:
        r = await _safe_post(
            ctx.client,
            f"{ctx.target_url}{test_path}",
            json={"name": "test", "is_admin": True, "role": "admin"},
        )
        if r is None or _method_not_supported(r):
            continue
        if r.status_code not in (200, 201):
            continue
        # Большинство API просто ИГНОРИРУЮТ лишние поля — это норма.
        # Подтверждаем read-back: поле должно реально присвоиться объекту.
        try:
            created = r.json()
        except ValueError:
            created = {}
        confirmed = isinstance(created, dict) and (
            created.get("is_admin") is True or str(created.get("role", "")).lower() == "admin"
        )
        if not confirmed:
            obj_id = created.get("id") if isinstance(created, dict) else None
            location = r.headers.get("location", "")
            read_url = None
            if location:
                read_url = location if location.startswith("http") else f"{ctx.target_url}{location}"
            elif obj_id is not None:
                read_url = f"{ctx.target_url}{test_path}/{obj_id}"
            if read_url:
                rr = await _safe_get(ctx.client, read_url)
                if rr is not None and rr.status_code == 200:
                    try:
                        obj = rr.json()
                    except ValueError:
                        obj = {}
                    confirmed = isinstance(obj, dict) and (
                        obj.get("is_admin") is True or str(obj.get("role", "")).lower() == "admin"
                    )
        if confirmed:
            findings.append(
                {
                    "level": "HIGH",
                    "type": "Mass Assignment",
                    "endpoint": test_path,
                    "desc": "Лишние поля (is_admin/role) реально присваиваются объекту — подтверждено read-back",
                    "details": get_vuln_info("Mass Assignment"),
                }
            )
            return findings
    return findings


# ================== GraphQL Introspection ==================
async def check_graphql_introspection(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    query = "{ __schema { types { name } } }"
    for path in ("/graphql", "/api/graphql", "/v1/graphql", "/gql"):
        r = await _safe_post(ctx.client, f"{ctx.target_url}{path}", json={"query": query})
        if r is None or r.status_code != 200:
            r = await _safe_get(ctx.client, f"{ctx.target_url}{path}", params={"query": query})
        if r is not None and r.status_code == 200 and "__schema" in _body(r):
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": "GraphQL Introspection",
                    "endpoint": path,
                    "desc": "Доступна GraphQL интроспекция",
                    "details": get_vuln_info("GraphQL Introspection"),
                }
            )
            return findings
    return findings
