"""
Поверхности атаки из OpenAPI-спеки.

Раньше сканер тестировал только path-параметры и только GET. Теперь для
каждого пути и метода (GET/POST/PUT/PATCH/DELETE) строятся «поверхности»:
path-параметры, query-параметры и тело запроса (пример генерируется из
JSON-схемы requestBody). Инъекции/XSS проверяются во всех этих местах.
"""

import copy
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .base import ScanContext, _safe_request

_METHODS = ("get", "post", "put", "patch", "delete")
_MAX_SURFACES = 40
_MAX_PARAMS_PER_SURFACE = 8
_SCHEMA_DEPTH = 4


def resolve_ref(spec: dict, ref: str) -> dict:
    """Разрешает локальный $ref вида #/components/schemas/User."""
    if not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def sample_from_schema(schema: Optional[dict], spec: dict, depth: int = 0) -> Any:
    """Генерирует валидный пример значения по JSON-схеме (для тел запросов)."""
    if not isinstance(schema, dict) or depth > _SCHEMA_DEPTH:
        return "test"
    if "$ref" in schema:
        return sample_from_schema(resolve_ref(spec, schema["$ref"]), spec, depth + 1)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return schema["enum"][0]
    if "allOf" in schema and isinstance(schema["allOf"], list):
        merged: Dict[str, Any] = {}
        for sub in schema["allOf"]:
            s = sample_from_schema(sub, spec, depth + 1)
            if isinstance(s, dict):
                merged.update(s)
        return merged or "test"
    t = schema.get("type")
    if t == "object" or (t is None and "properties" in schema):
        props = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        out: Dict[str, Any] = {}
        for name, sub in list(props.items())[:_MAX_PARAMS_PER_SURFACE]:
            if required and name not in required and len(out) >= 3:
                continue
            out[name] = sample_from_schema(sub, spec, depth + 1)
        return out
    if t == "array":
        return [sample_from_schema(schema.get("items") or {}, spec, depth + 1)]
    if t == "integer":
        return 1
    if t == "number":
        return 1.5
    if t == "boolean":
        return True
    if t == "null":
        return None
    return "test"


@dataclass
class Surface:
    """Один эндпоинт+метод со всеми инъекционными точками."""
    path: str
    method: str
    path_params: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, Any] = field(default_factory=dict)
    body: Optional[Any] = None
    # (kind, name): kind in {"path", "query", "body"}
    injectable: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


def _body_injectable_fields(body: Any) -> List[str]:
    """Поля верхнего уровня, куда можно injecting строковый payload."""
    if not isinstance(body, dict):
        return []
    return [k for k, v in body.items() if isinstance(v, (str, int, float))][:_MAX_PARAMS_PER_SURFACE]


def build_surfaces(ctx: ScanContext, limit: int = _MAX_SURFACES) -> List[Surface]:
    """
    Строит поверхности атаки по спеке. Без спеки — fallback: GET-поверхности
    из списка эндпоинтов с path-параметрами (старое поведение).
    """
    spec = ctx.openapi or {}
    paths = spec.get("paths")
    surfaces: List[Surface] = []
    if isinstance(paths, dict) and paths:
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method in _METHODS:
                op = item.get(method)
                if not isinstance(op, dict):
                    continue
                s = Surface(path=path, method=method)
                params = list(item.get("parameters") or []) + list(op.get("parameters") or [])
                for p in params:
                    if not isinstance(p, dict):
                        continue
                    name = p.get("name")
                    if not name:
                        continue
                    schema = p.get("schema") or {}
                    sample = sample_from_schema(schema, spec)
                    if p.get("in") == "path":
                        s.path_params[name] = str(sample if sample is not None else "1")
                        s.injectable.append(("path", name))
                    elif p.get("in") == "query":
                        s.query[name] = sample
                        s.injectable.append(("query", name))
                body_schema = (
                    ((op.get("requestBody") or {}).get("content") or {})
                    .get("application/json", {})
                    .get("schema")
                )
                if body_schema:
                    s.body = sample_from_schema(body_schema, spec)
                    for fname in _body_injectable_fields(s.body):
                        s.injectable.append(("body", fname))
                s.injectable = s.injectable[:_MAX_PARAMS_PER_SURFACE]
                surfaces.append(s)
                if len(surfaces) >= limit:
                    return surfaces
        return surfaces
    # fallback без спеки
    for ep in ctx_endpoints_fallback(ctx):
        s = Surface(path=ep, method="get")
        for part in ep.split("/"):
            if part.startswith("{") and part.endswith("}"):
                name = part[1:-1]
                s.path_params[name] = "1"
                s.injectable.append(("path", name))
        surfaces.append(s)
        if len(surfaces) >= limit:
            break
    return surfaces


def ctx_endpoints_fallback(ctx: ScanContext) -> List[str]:
    """Эндпоинты без спеки берутся из переданного списка (см. scan_engine)."""
    return list(getattr(ctx, "_endpoints", []) or [])


def build_url_query_body(
    s: Surface,
    path_over: Optional[Dict[str, str]] = None,
    query_over: Optional[Dict[str, Any]] = None,
    body_over: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any], Optional[Any]]:
    """Собирает path (с подстановками), query и тело для запроса."""
    path = s.path
    for name, val in {**s.path_params, **(path_over or {})}.items():
        path = path.replace("{" + name + "}", urllib.parse.quote(str(val), safe=""))
    query = {**s.query, **(query_over or {})}
    body = copy.deepcopy(s.body) if s.body is not None else None
    if body_over and isinstance(body, dict):
        body.update(body_over)
    return path, query, body


async def probe(
    ctx: ScanContext,
    s: Surface,
    path_over: Optional[Dict[str, str]] = None,
    query_over: Optional[Dict[str, Any]] = None,
    body_over: Optional[Dict[str, Any]] = None,
    client=None,
):
    """Отправляет запрос по поверхности (через общий _safe_request: бюджет/evidence)."""
    path, query, body = build_url_query_body(s, path_over, query_over, body_over)
    url = f"{ctx.target_url}{path}"
    kwargs: Dict[str, Any] = {}
    if query:
        kwargs["params"] = query
    if body is not None and s.method in ("post", "put", "patch"):
        kwargs["json"] = body
    return await _safe_request(client or ctx.client, s.method.upper(), url, **kwargs)
