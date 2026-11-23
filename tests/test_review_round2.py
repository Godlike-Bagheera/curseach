"""Регрессии round-2 ревью: JWT-итерация/бюджет, SQLi 2xx baseline, планировщик.

1. check_jwt_weak_secret больше не завершается на первом публичном кандидате.
2. Публичные эндпоинты не расходуют бюджет tried в check_jwt_none/exp.
3. Boolean-SQLi baseline принимает любой 2xx (не только 200).
4. run_due_schedules регистрирует задачу в tasks (чистится _gc_sweep, отменяема).
"""

import asyncio

import httpx

from checks.auth import check_jwt_exp, check_jwt_none, check_jwt_weak_secret
from checks.base import ScanContext
from checks.injection import check_sqli


def _run(fn, handler, endpoints, spec=None):
    async def runner():
        transport = httpx.MockTransport(handler)
        async with (
            httpx.AsyncClient(transport=transport) as c,
            httpx.AsyncClient(transport=transport) as anon,
        ):
            ctx = ScanContext(target_url="http://t", client=c, anon_client=anon, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


# ---------- 1. JWT weak secret: уязвимый эндпоинт после публичных ----------
# Публичные: 200 всем. Уязвимый: 401 без токена, любой Bearer принимается.
def _weak_handler(r):
    if r.url.path == "/api/protected/{id}".replace("{id}", "1"):
        if not r.headers.get("authorization"):
            return httpx.Response(401)
        return httpx.Response(200, json={"secret": "x"})
    return httpx.Response(200, json={"public": True})


_VULN_EP = "/api/protected/{id}"
_PUBLIC_EPS = [f"/api/catalog{i}/{{id}}" for i in range(6)]


def test_jwt_weak_secret_found_after_public_candidates():
    f = _run(check_jwt_weak_secret, _weak_handler, _PUBLIC_EPS + [_VULN_EP])
    assert len(f) == 1 and f[0]["type"] == "JWT Weak Secret"
    assert f[0]["endpoint"] == _VULN_EP


def test_jwt_none_found_after_public_candidates():
    f = _run(check_jwt_none, _weak_handler, _PUBLIC_EPS + [_VULN_EP])
    assert len(f) == 1 and f[0]["type"] == "JWT alg=none"
    assert f[0]["endpoint"] == _VULN_EP


def test_jwt_exp_found_after_public_candidates():
    f = _run(check_jwt_exp, _weak_handler, _PUBLIC_EPS + [_VULN_EP])
    assert len(f) == 1 and f[0]["type"] == "JWT Expiration Not Verified"
    assert f[0]["endpoint"] == _VULN_EP


# ---------- 2. Публичные эндпоинты не расходуют бюджет tried (кап 8) ----------
def test_jwt_none_budget_not_consumed_by_public():
    # 10 публичных + 8 защищённых уязвимых. Бюджет 8 должен хватить на все 8
    # защищённых (раньше публичные съедали бюджет и часть оставалась нетестированной).
    def handler(r):
        if "/api/pub" in r.url.path:
            return httpx.Response(200, json={"public": True})
        if not r.headers.get("authorization"):
            return httpx.Response(401)
        return httpx.Response(200, json={"secret": "x"})

    eps = [f"/api/pub{i}/{{id}}" for i in range(10)] + [f"/api/sec{i}/{{id}}" for i in range(8)]
    f = _run(check_jwt_none, handler, eps)
    # Первый подтверждённый — флагается, дальше проверка останавливается.
    assert len(f) == 1 and f[0]["type"] == "JWT alg=none"
    assert f[0]["endpoint"].startswith("/api/sec")


# ---------- 3. SQLi boolean: baseline 201 (2xx) — детект работает ----------
def test_sqli_boolean_baseline_201_still_flagged():
    # Путь-параметр id: baseline "1" → 201; "1 AND 1=1" → то же тело, что baseline;
    # "1 AND 1=2" → другое тело. Boolean-динамика налицо.
    body_ok = '{"id": 1, "name": "widget"}'
    headers = {"content-type": "application/json"}

    def handler(r):
        idval = r.url.path.rsplit("/", 1)[-1]
        if idval == "1":
            return httpx.Response(201, content=body_ok.encode(), headers=headers)
        if "AND 1=1" in idval:
            return httpx.Response(200, content=body_ok.encode(), headers=headers)
        if "AND 1=2" in idval:
            return httpx.Response(200, content=b'{"id": 0}', headers=headers)
        return httpx.Response(200, json={})

    f = _run(check_sqli, handler, ["/api/items/{id}"])
    assert any(x["type"] == "SQL Injection" for x in f)
