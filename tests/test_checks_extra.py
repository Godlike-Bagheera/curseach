"""Прицельные тесты checks/logic.py, checks/headers.py, checks/misc.py (MockTransport)."""

import asyncio
import datetime

import httpx

from checks import headers, logic, misc
from checks.base import ScanContext


def _check(check_fn, handler, endpoints, spec=None, target="http://t"):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(target_url=target, client=c, anon_client=c, openapi=spec)
            return await check_fn(ctx, endpoints)

    return asyncio.run(run())


# ---------- logic: business logic ----------
def test_business_logic_positive():
    f = _check(
        logic.check_business_logic, lambda r: httpx.Response(200, json={"data": [{"id": 1}]}), ["/api/users/{id}"]
    )
    assert len(f) == 1 and f[0]["type"] == "Business Logic Error"


def test_business_logic_error_body():
    assert (
        _check(logic.check_business_logic, lambda r: httpx.Response(200, json={"error": "bad"}), ["/api/users/{id}"])
        == []
    )


def test_business_logic_non200():
    assert _check(logic.check_business_logic, lambda r: httpx.Response(404, text="no"), ["/api/users/{id}"]) == []


# ---------- logic: _count_items ----------
def test_count_items():
    assert logic._count_items([1, 2, 3]) == 3
    assert logic._count_items({"data": [1, 2]}) == 2
    assert logic._count_items({"items": [1]}) == 1
    assert logic._count_items({"results": []}) == 0
    assert logic._count_items({"rows": [1, 2, 3, 4]}) == 4
    assert logic._count_items({"other": 1}) == 0
    assert logic._count_items("str") == 0


# ---------- logic: pagination ----------
def test_pagination_missing():
    f = _check(logic.check_pagination, lambda r: httpx.Response(200, json={"data": list(range(150))}), ["/api/items"])
    assert len(f) == 1 and f[0]["type"] == "Missing Pagination"


def test_pagination_ok():
    assert (
        _check(logic.check_pagination, lambda r: httpx.Response(200, json={"data": list(range(5))}), ["/api/items"])
        == []
    )


# ---------- logic: mass assignment ----------
def test_mass_assignment():
    spec = {"paths": {"/api/items": {"post": {}}}}
    f = _check(logic.check_mass_assignment, lambda r: httpx.Response(201, json={"ok": True}), ["/api/items"], spec=spec)
    assert len(f) == 1 and f[0]["type"] == "Mass Assignment"


# ---------- logic: graphql ----------
def test_graphql_introspection():
    f = _check(
        logic.check_graphql_introspection, lambda r: httpx.Response(200, json={"data": {"__schema": {"types": []}}}), []
    )
    assert len(f) == 1 and f[0]["type"] == "GraphQL Introspection"


def test_graphql_absent():
    assert _check(logic.check_graphql_introspection, lambda r: httpx.Response(404, text="no"), []) == []


# ---------- headers: security headers ----------
def test_security_headers_missing():
    f = _check(headers.check_security_headers, lambda r: httpx.Response(200, text="ok"), [])
    assert len(f) == 4


def test_security_headers_present():
    hdrs = {
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
    }
    assert _check(headers.check_security_headers, lambda r: httpx.Response(200, text="ok", headers=hdrs), []) == []


# ---------- headers: unsafe methods ----------
def test_unsafe_methods():
    f = _check(
        headers.check_unsafe_methods, lambda r: httpx.Response(200, headers={"allow": "GET, PUT, DELETE, TRACE"}), ["/"]
    )
    assert len(f) == 1 and f[0]["type"] == "Unsafe HTTP Methods"


def test_safe_methods():
    assert (
        _check(headers.check_unsafe_methods, lambda r: httpx.Response(200, headers={"allow": "GET, HEAD"}), ["/"]) == []
    )


# ---------- headers: TLS (probe замокан) ----------
def test_tls_non_https():
    assert _check(headers.check_tls_version, lambda r: httpx.Response(200), [], target="http://t") == []


def test_tls_weak(monkeypatch):
    monkeypatch.setattr(headers, "_tls_probe", lambda host, port: {"version": "TLSv1", "trusted": True})
    f = _check(headers.check_tls_version, lambda r: httpx.Response(200), [], target="https://t")
    assert any(x["type"] == "Weak TLS Version" for x in f)


def test_tls_untrusted(monkeypatch):
    monkeypatch.setattr(headers, "_tls_probe", lambda host, port: {"version": "TLSv1.3", "trusted": False})
    f = _check(headers.check_tls_version, lambda r: httpx.Response(200), [], target="https://t")
    assert any(x["type"] == "TLS Certificate Untrusted" for x in f)


def test_tls_expired(monkeypatch):
    past = datetime.datetime.now(datetime.timezone.utc).timestamp() - 86400
    monkeypatch.setattr(
        headers, "_tls_probe", lambda host, port: {"version": "TLSv1.3", "trusted": True, "expires_ts": past}
    )
    f = _check(headers.check_tls_version, lambda r: httpx.Response(200), [], target="https://t")
    assert any(x["type"] == "TLS Certificate Expired" for x in f)


def test_tls_expiring_soon(monkeypatch):
    soon = datetime.datetime.now(datetime.timezone.utc).timestamp() + 5 * 86400
    monkeypatch.setattr(
        headers, "_tls_probe", lambda host, port: {"version": "TLSv1.3", "trusted": True, "expires_ts": soon}
    )
    f = _check(headers.check_tls_version, lambda r: httpx.Response(200), [], target="https://t")
    assert any(x["type"] == "TLS Certificate Expiring Soon" for x in f)


# ---------- misc: hidden paths ----------
def test_hidden_paths():
    def handler(request):
        return httpx.Response(403) if request.url.path == "/admin" else httpx.Response(404)

    f = _check(misc.check_hidden_paths, handler, [])
    assert len(f) == 1 and f[0]["endpoint"] == "/admin"


# ---------- misc: http only ----------
def test_http_only():
    f = _check(misc.check_http_only, lambda r: httpx.Response(200), [], target="http://t")
    assert len(f) == 1 and f[0]["type"] == "HTTP without HTTPS"


def test_https_only():
    assert _check(misc.check_http_only, lambda r: httpx.Response(200), [], target="https://t") == []


# ---------- misc: content-type ----------
def test_content_type_validation():
    spec = {"paths": {"/api/items": {"post": {}}}}
    f = _check(
        misc.check_content_type_validation, lambda r: httpx.Response(200, json={"ok": True}), ["/api/items"], spec=spec
    )
    assert len(f) == 1 and f[0]["type"] == "Missing Content-Type Validation"


# ---------- misc: rate limiting ----------
def test_rate_limiting_missing():
    f = _check(misc.check_rate_limiting, lambda r: httpx.Response(200, text="ok"), ["/"])
    assert len(f) == 1 and f[0]["type"] == "Lack of Rate Limiting"


def test_rate_limiting_present():
    assert _check(misc.check_rate_limiting, lambda r: httpx.Response(429, text="slow down"), ["/"]) == []
