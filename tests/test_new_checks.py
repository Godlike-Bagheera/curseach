"""Новые проверки: Path Traversal, Open Redirect, Insecure Cookie Flags."""

import asyncio

import httpx

from checks.cookies import check_cookie_flags
from checks.traversal import check_open_redirect, check_path_traversal
from scanner.vuln_guide import build_registry, slugify


def _run(fn, handler, endpoints, spec=None):
    async def runner():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as anon,
        ):
            from checks.base import ScanContext

            ctx = ScanContext(target_url="http://t", client=c, anon_client=anon, openapi=spec)
            return await fn(ctx, endpoints)

    return asyncio.run(runner())


_FILE_SPEC = {
    "paths": {"/api/file": {"get": {"parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}}]}}}
}
_REDIR_SPEC = {
    "paths": {"/api/redirect": {"get": {"parameters": [{"name": "next", "in": "query", "schema": {"type": "string"}}]}}}
}


def test_path_traversal_flagged():
    f = _run(
        check_path_traversal,
        lambda r: httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash"),
        ["/api/file"],
        _FILE_SPEC,
    )
    assert len(f) == 1 and f[0]["type"] == "Path Traversal" and f[0]["param"] == "name"


def test_path_traversal_safe_not_flagged():
    assert (
        _run(check_path_traversal, lambda r: httpx.Response(200, json={"content": "normal"}), ["/api/file"], _FILE_SPEC)
        == []
    )


def test_open_redirect_flagged():
    def handler(r):
        return httpx.Response(302, headers={"location": r.url.params.get("next", "/")})

    f = _run(check_open_redirect, handler, ["/api/redirect"], _REDIR_SPEC)
    assert len(f) == 1 and f[0]["type"] == "Open Redirect"


def test_open_redirect_relative_not_flagged():
    def handler(r):
        nxt = r.url.params.get("next", "/")
        return httpx.Response(302, headers={"location": nxt if nxt.startswith("/") else "/"})

    assert _run(check_open_redirect, handler, ["/api/redirect"], _REDIR_SPEC) == []


def test_cookie_flags_insecure():
    def handler(r):
        return httpx.Response(200, headers={"set-cookie": "session_id=abc; Path=/"})

    f = _run(check_cookie_flags, handler, ["/api/session/login"])
    assert any(x["type"] == "Insecure Cookie Flags" for x in f)


def test_cookie_flags_secure_not_flagged():
    def handler(r):
        return httpx.Response(200, headers={"set-cookie": "session_id=abc; Secure; HttpOnly; SameSite=Lax"})

    assert _run(check_cookie_flags, handler, ["/api/session/login"]) == []


def test_new_types_have_registry_anchors():
    reg = {r["id"]: r for r in build_registry()}
    assert slugify("Path Traversal") in reg["check_path_traversal"]["anchors"]
    assert slugify("Open Redirect") in reg["check_open_redirect"]["anchors"]
    assert slugify("Insecure Cookie Flags") in reg["check_cookie_flags"]["anchors"]
