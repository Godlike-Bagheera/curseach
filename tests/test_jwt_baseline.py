"""JWT-проверки не флагуется на публичных эндпоинтах (baseline: аноним без токена → 200).

Регрессия: check_jwt_none/exp/weak_secret раньше флагали любой 200-эндпоинт,
включая публичные каталоги. Теперь эндпоинт обязан реально требовать auth
(без токена → не 200); только тогда принятие поддельного токена — уязвимость.
"""

import asyncio

import httpx

from checks.auth import check_jwt_exp, check_jwt_none, check_jwt_weak_secret
from checks.base import ScanContext


def _run(fn, handler, endpoints, spec=None):
    async def runner():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as anon,
        ):
            ctx = ScanContext(target_url="http://t", client=c, anon_client=anon, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


_SPEC = {"paths": {"/api/reports/{id}": {"get": {"responses": {"401": {}}}}}}


def _public(r):
    # Публичный каталог: 200 всем, никакой JWT-уязвимости нет.
    return httpx.Response(200, json={"id": 1, "name": "widget", "price": 10})


def _protected(r):
    # Защищённый эндпоинт: без токена 401, поддельный Bearer принимается (200).
    if not r.headers.get("authorization"):
        return httpx.Response(401)
    return httpx.Response(200, json={"data": "x"})


def test_jwt_none_public_not_flagged():
    assert _run(check_jwt_none, _public, ["/api/reports/{id}"], _SPEC) == []


def test_jwt_exp_public_not_flagged():
    assert _run(check_jwt_exp, _public, ["/api/reports/{id}"], _SPEC) == []


def test_jwt_weak_public_not_flagged():
    assert _run(check_jwt_weak_secret, _public, ["/api/reports/{id}"], _SPEC) == []


def test_jwt_none_protected_flagged():
    f = _run(check_jwt_none, _protected, ["/api/reports/{id}"], _SPEC)
    assert len(f) == 1 and f[0]["type"] == "JWT alg=none"


def test_jwt_exp_protected_flagged():
    f = _run(check_jwt_exp, _protected, ["/api/reports/{id}"], _SPEC)
    assert len(f) == 1 and f[0]["type"] == "JWT Expiration Not Verified"


def test_jwt_weak_protected_flagged():
    f = _run(check_jwt_weak_secret, _protected, ["/api/reports/{id}"], _SPEC)
    assert len(f) == 1 and f[0]["type"] == "JWT Weak Secret"
