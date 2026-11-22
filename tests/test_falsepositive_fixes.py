"""Регрессии на 6 ложных срабатываний: здоровый сервис → нет находки, уязвимый → есть.

SQLi baseline-дифференциал, IDOR public-endpoints, CSRF Bearer-only,
CAPTCHA только реальные login-пути, HTTP-only severity по хосту,
сигнатуры вывода ОС-команд.
"""

import asyncio

import httpx

from checks.access import check_captcha, check_csrf, check_idor
from checks.base import ScanContext
from checks.injection import check_command_injection, check_sqli
from checks.misc import check_http_only


def _run(fn, handler, endpoints, spec=None, target="http://t", headers=None, cookies=None):
    async def runner():
        transport = httpx.MockTransport(handler)
        async with (
            httpx.AsyncClient(transport=transport, headers=headers or {}, cookies=cookies or {}) as c,
            httpx.AsyncClient(transport=transport) as anon,
        ):
            ctx = ScanContext(target_url=target, client=c, anon_client=anon, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


# ---------- 1. SQLi: 500-on-payload только при не-500 baseline ----------
def test_sqli_500_on_any_input_not_flagged():
    # Эндпоинт падает и на безобидном «1», и на payload — это не SQLi.
    assert _run(check_sqli, lambda r: httpx.Response(500, text="boom"), ["/api/items/{id}"]) == []


def test_sqli_500_only_on_payload_flagged():
    def handler(r):
        if r.url.path == "/api/items/1":
            return httpx.Response(200, json={"data": [{"id": 1}]})
        return httpx.Response(500, text="boom")

    f = _run(check_sqli, handler, ["/api/items/{id}"])
    assert any(x["type"] == "SQL Injection" for x in f)


def test_sqli_error_text_flagged_even_when_baseline_500():
    def handler(r):
        if r.url.path == "/api/items/1":
            return httpx.Response(500, text="boom")
        return httpx.Response(500, text="You have an error in your SQL syntax")

    f = _run(check_sqli, handler, ["/api/items/{id}"])
    assert any(x["type"] == "SQL Injection" for x in f)


# ---------- 2. IDOR: явно публичные параметрические эндпоинты ----------
_PUBLIC_SPEC = {
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/api/products/{id}": {"get": {"security": []}},
        "/api/orders/{id}": {"get": {"security": [{"bearer": []}]}},
    },
}


def test_idor_skips_explicitly_public_param_endpoint():
    def handler(r):
        return httpx.Response(200, json={"id": r.url.path.rsplit("/", 1)[-1], "name": "x"})

    f = _run(check_idor, handler, ["/api/products/{id}", "/api/orders/{id}"], spec=_PUBLIC_SPEC)
    assert [x["endpoint"] for x in f] == ["/api/orders/{id}"]


def test_idor_param_ownership_endpoint_without_spec_still_flagged():
    def handler(r):
        return httpx.Response(200, json={"id": r.url.path.rsplit("/", 1)[-1], "user_id": 2, "item": "x"})

    f = _run(check_idor, handler, ["/api/orders/{id}"])
    assert any(x["endpoint"] == "/api/orders/{id}" for x in f)


# ---------- 3. CSRF: Bearer-only API без cookies не флагуется ----------
_CSRF_SPEC = {"paths": {"/api/items": {"post": {}}}}


def test_csrf_bearer_only_without_cookies_skipped():
    f = _run(
        check_csrf,
        lambda r: httpx.Response(200, json={"ok": True}),
        ["/api/items"],
        spec=_CSRF_SPEC,
        headers={"Authorization": "Bearer token123"},
    )
    assert f == []


def test_csrf_bearer_with_set_cookie_flagged():
    f = _run(
        check_csrf,
        lambda r: httpx.Response(200, json={"ok": True}, headers={"set-cookie": "session=abc; Path=/"}),
        ["/api/items"],
        spec=_CSRF_SPEC,
        headers={"Authorization": "Bearer token123"},
    )
    assert len(f) == 1 and f[0]["type"] == "Missing CSRF Protection"


def test_csrf_cookie_session_flagged():
    f = _run(
        check_csrf,
        lambda r: httpx.Response(200, json={"ok": True}),
        ["/api/items"],
        spec=_CSRF_SPEC,
        cookies={"session": "abc"},
    )
    assert len(f) == 1 and f[0]["type"] == "Missing CSRF Protection"


# ---------- 4. CAPTCHA: только реальные login-эндпоинты ----------
def test_captcha_login_404_not_flagged():
    assert _run(check_captcha, lambda r: httpx.Response(404), ["/api/auth/login"]) == []


def test_captcha_login_405_not_flagged():
    assert _run(check_captcha, lambda r: httpx.Response(405), ["/api/auth/login"]) == []


def test_captcha_server_error_not_flagged():
    assert _run(check_captcha, lambda r: httpx.Response(500), ["/api/auth/login"]) == []


def test_captcha_real_login_401_flagged():
    f = _run(check_captcha, lambda r: httpx.Response(401, json={"detail": "Invalid credentials"}), ["/api/auth/login"])
    assert len(f) == 1 and f[0]["type"] == "Lack of CAPTCHA"


def test_captcha_429_protection_not_flagged():
    assert _run(check_captcha, lambda r: httpx.Response(429), ["/api/auth/login"]) == []


# ---------- 5. HTTP-only: loopback/приватные → LOW, публичный → MEDIUM ----------
def test_http_only_localhost_low():
    f = _run(check_http_only, lambda r: httpx.Response(200), [], target="http://127.0.0.1:8000")
    assert len(f) == 1 and f[0]["level"] == "LOW" and f[0]["type"] == "HTTP without HTTPS"


def test_http_only_private_host_low():
    f = _run(check_http_only, lambda r: httpx.Response(200), [], target="http://192.168.0.10:8000")
    assert f[0]["level"] == "LOW"


def test_http_only_public_host_medium():
    f = _run(check_http_only, lambda r: httpx.Response(200), [], target="http://api.example.com")
    assert f[0]["level"] == "MEDIUM"


# ---------- 6. Command injection: сигнатуры реального вывода команд ----------
def test_cmdinj_plain_root_colon_not_flagged():
    assert (
        _run(check_command_injection, lambda r: httpx.Response(200, text="root: доступ запрещён"), ["/api/ping/{host}"])
        == []
    )


def test_cmdinj_uid_without_gid_not_flagged():
    assert _run(check_command_injection, lambda r: httpx.Response(200, text="uid=1000"), ["/api/ping/{host}"]) == []


def test_cmdinj_id_output_flagged():
    f = _run(
        check_command_injection,
        lambda r: httpx.Response(200, json={"output": "uid=0(root) gid=0(root) groups=0(root)"}),
        ["/api/ping/{host}"],
    )
    assert len(f) == 1 and f[0]["type"] == "OS Command Injection"


def test_cmdinj_passwd_output_flagged():
    f = _run(
        check_command_injection,
        lambda r: httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash"),
        ["/api/ping/{host}"],
    )
    assert len(f) == 1 and f[0]["type"] == "OS Command Injection"
