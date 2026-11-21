"""Дожатые эвристики: тишина на healthy-целях, детекция на уязвимых.

Path traversal (passwd-структура вместо голых /bin/sh), sensitive-data (пропуск
placeholder/масок), IDOR без 2 токенов (ownership-сигнал), rate-limit (только API/auth).
"""

import asyncio

import httpx

from checks.access import check_idor, check_idor_auth
from checks.base import ScanContext
from checks.data import check_sensitive_data
from checks.misc import check_rate_limiting
from checks.traversal import check_path_traversal


def _run(fn, handler, endpoints, spec=None, has_auth=False, target="http://t"):
    async def runner():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as anon,
        ):
            ctx = ScanContext(target_url=target, client=c, anon_client=anon, has_auth=has_auth, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


# ---------- 1. Path traversal: голые /bin/sh / /bin/bash — не сигнатура ----------
_FILE_SPEC = {
    "paths": {"/api/file": {"get": {"parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}}]}}}
}


def test_traversal_bare_shell_paths_not_flagged():
    f = _run(
        check_path_traversal,
        lambda r: httpx.Response(200, text="Allowed shells: /bin/sh, /bin/bash, /bin/zsh"),
        ["/api/file"],
        _FILE_SPEC,
    )
    assert f == []


def test_traversal_passwd_flagged():
    f = _run(
        check_path_traversal,
        lambda r: httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash"),
        ["/api/file"],
        _FILE_SPEC,
    )
    assert len(f) == 1 and f[0]["type"] == "Path Traversal"


# ---------- 2. Sensitive data: placeholder/маски — не утечка ----------
def test_sensitive_password_placeholder_not_flagged():
    f = _run(
        check_sensitive_data,
        lambda r: httpx.Response(200, json={"password": "string"}),
        ["/api/config"],
    )
    assert f == []


def test_sensitive_password_masked_not_flagged():
    f = _run(
        check_sensitive_data,
        lambda r: httpx.Response(200, json={"password": "********"}),
        ["/api/config"],
    )
    assert f == []


def test_sensitive_real_password_flagged():
    f = _run(
        check_sensitive_data,
        lambda r: httpx.Response(200, json={"password": "Sup3rS3cret!2024"}),
        ["/api/config"],
    )
    assert len(f) == 1 and f[0]["type"] == "Sensitive Data Exposure"


def test_sensitive_aws_key_flagged():
    f = _run(
        check_sensitive_data,
        lambda r: httpx.Response(200, json={"aws_key": "AKIAIOSFODNN7EXAMPLE"}),
        ["/api/config"],
    )
    assert len(f) == 1 and f[0]["type"] == "Sensitive Data Exposure"


# ---------- 3. IDOR без 2 токенов: ownership-сигнал ----------
def test_idor_public_catalog_not_flagged():
    def handler(r):
        return httpx.Response(200, json={"id": r.url.path.rsplit("/", 1)[-1], "name": "widget", "price": 10})

    assert _run(check_idor, handler, ["/api/products/{id}"]) == []


def test_idor_ownership_flagged():
    def handler(r):
        return httpx.Response(200, json={"id": r.url.path.rsplit("/", 1)[-1], "user_id": 2, "item": "x"})

    f = _run(check_idor, handler, ["/api/orders/{id}"])
    assert any(x["endpoint"] == "/api/orders/{id}" for x in f)


def test_idor_auth_public_collection_not_flagged():
    f = _run(
        check_idor_auth,
        lambda r: httpx.Response(200, json={"items": [{"id": 1, "name": "widget"}]}),
        ["/api/products"],
        has_auth=True,
    )
    assert f == []


def test_idor_auth_sensitive_flagged():
    f = _run(check_idor_auth, lambda r: httpx.Response(200, json={"secret": "x"}), ["/api/system/keys"], has_auth=True)
    assert len(f) == 1 and f[0]["level"] == "MEDIUM"


# ---------- 4. Rate-limit: только API/auth, не голый корень ----------
def test_rate_limit_root_not_flagged():
    assert _run(check_rate_limiting, lambda r: httpx.Response(200, text="ok"), ["/"]) == []


def test_rate_limit_api_flagged():
    f = _run(check_rate_limiting, lambda r: httpx.Response(200, text="ok"), ["/api/items"])
    assert len(f) == 1 and f[0]["type"] == "Lack of Rate Limiting"


def test_rate_limit_auth_flagged():
    f = _run(check_rate_limiting, lambda r: httpx.Response(200, json={"ok": True}), ["/api/auth/login"])
    assert len(f) == 1 and f[0]["endpoint"] == "/api/auth/login"
