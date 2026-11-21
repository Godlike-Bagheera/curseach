"""SPA catch-all не должен давать ложных CRITICAL/Rate-Limiting (MiRiAl-кейс)."""

import asyncio

import httpx

from checks.access import check_idor, check_idor_auth
from checks.base import ScanContext, _is_html, _is_spa_shell
from checks.discovery import discover_endpoints
from checks.misc import check_rate_limiting

SPA = '<!doctype html><html lang="ru"><head><title>LMS</title></head><body><div id="root"></div></body></html>'


def _spa():
    return httpx.Response(200, text=SPA, headers={"content-type": "text/html"})


def _run(fn, handler, endpoints, spec=None, has_auth=False):
    async def runner():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as anon,
        ):
            ctx = ScanContext(target_url="http://t", client=c, anon_client=anon, has_auth=has_auth, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


def test_is_spa_shell_markers():
    assert _is_spa_shell(SPA)
    assert _is_spa_shell("<html><body><app-root></app-root></body></html>")
    assert not _is_spa_shell("<html><body>Admin panel (unlisted)</body></html>")
    assert not _is_spa_shell('{"aws_key":"x"}')
    assert not _is_spa_shell("ok")


def test_is_html():
    assert _is_html(_spa())
    assert not _is_html(httpx.Response(200, text="ok"))
    assert not _is_html(httpx.Response(200, json={"a": 1}))


def test_idor_sensitive_spa_catchall_not_flagged():
    f = _run(check_idor, lambda r: _spa(), ["/admin", "/config", "/debug"])
    assert f == []


def test_idor_sensitive_real_json_flagged():
    def handler(r):
        if r.url.path == "/api/system/keys":
            return httpx.Response(200, json={"aws_key": "AKIAIOSFODNN7EXAMPLE"})
        return httpx.Response(404, json={"detail": "Not Found"})

    f = _run(check_idor, handler, ["/api/system/keys"])
    assert any(x["level"] == "CRITICAL" and x["endpoint"] == "/api/system/keys" for x in f)


def test_idor_sensitive_real_html_admin_flagged():
    admin_html = "<html><body>Admin panel (unlisted)</body></html>"

    def handler(r):
        if r.url.path == "/admin":
            return httpx.Response(200, text=admin_html, headers={"content-type": "text/html"})
        return httpx.Response(404)

    assert any(x["endpoint"] == "/admin" for x in _run(check_idor, handler, ["/admin"]))


def test_idor_auth_spa_not_flagged():
    f = _run(check_idor_auth, lambda r: _spa(), ["/api/private"], has_auth=True)
    assert f == []


def test_discovery_spa_catchall_filtered():
    def handler(r):
        if r.url.path in ("/robots.txt", "/sitemap.xml"):
            return httpx.Response(404)
        return _spa()

    async def runner():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c)
            return await discover_endpoints(ctx)

    found = asyncio.run(runner())
    assert "/admin" not in found and "/config" not in found and "/debug" not in found


def test_rate_limiting_spa_skipped():
    assert (
        _run(
            check_rate_limiting,
            lambda r: _spa(),
            ["/"],
        )
        == []
    )


def test_rate_limiting_prefers_auth_route():
    calls = []

    def handler(r):
        calls.append(r.url.path)
        return httpx.Response(200, json={"ok": True})

    f = _run(check_rate_limiting, handler, ["/", "/api/auth/login", "/api/items"])
    assert "/api/auth/login" in calls
    assert f and f[0]["endpoint"] == "/api/auth/login"


def test_rate_limiting_skips_probe_paths():
    calls = []

    def handler(r):
        calls.append(r.url.path)
        return httpx.Response(200, text="ok")

    f = _run(check_rate_limiting, handler, ["/.env", "/api/items"])
    assert "/.env" not in calls
    assert f and f[0]["endpoint"] == "/api/items"
