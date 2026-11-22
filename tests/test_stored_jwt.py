"""Stored XSS и JWT exp — новые проверки."""

import asyncio

import httpx

from checks.auth import check_jwt_exp
from checks.base import ScanContext
from checks.xss import check_stored_xss


def _run(fn, handler, endpoints, spec=None):
    async def runner():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as anon,
        ):
            ctx = ScanContext(target_url="http://t", client=c, anon_client=anon, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


def test_stored_xss_flagged():
    store = []

    def handler(r):
        if r.method == "POST":
            import json

            store.append(json.loads(r.content).get("comment", ""))
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(
            200,
            text="<html><ul>" + "".join(f"<li>{c}</li>" for c in store) + "</ul></html>",
            headers={"content-type": "text/html"},
        )

    spec = {"paths": {"/api/comments": {"post": {}, "get": {}}}}
    f = _run(check_stored_xss, handler, ["/api/comments"], spec)
    assert len(f) == 1 and f[0]["type"] == "Stored XSS"


def test_jwt_exp_flagged():
    spec = {"paths": {"/api/reports/{id}": {"get": {"responses": {"401": {}}}}}}

    def handler(r):
        # Защищённый эндпоинт: без токена 401, поддельный токен принимается (200).
        if not r.headers.get("authorization"):
            return httpx.Response(401)
        return httpx.Response(200, json={"data": "x"})

    f = _run(check_jwt_exp, handler, ["/api/reports/{id}"], spec)
    assert len(f) == 1 and f[0]["type"] == "JWT Expiration Not Verified"
