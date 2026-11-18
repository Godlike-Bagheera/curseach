"""Юнит-тесты проверок на httpx.MockTransport — без реальной сети."""
import asyncio

import httpx

from checks.base import ScanContext, _writable_endpoints
from checks.xss import check_xss
from checks.data import check_sca
from checks.access import check_idor_auth, check_csrf
from checks.headers import check_security_headers


def _run_check(check_fn, handler, endpoints, spec=None, has_auth=True):
    async def runner():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client, \
                   httpx.AsyncClient(transport=transport) as anon:
            ctx = ScanContext(target_url="http://t", client=client, anon_client=anon,
                              has_auth=has_auth, openapi=spec)
            return await check_fn(ctx, endpoints)
    return asyncio.run(runner())


def test_writable_endpoints_filters_by_spec_methods():
    spec = {"paths": {"/": {"get": {}}, "/api/items": {"post": {}},
                      "/api/auth/login": {"post": {}}, "/api/users/{id}": {"get": {}}}}
    ctx = ScanContext(target_url="http://t", client=None, anon_client=None, openapi=spec)
    assert _writable_endpoints(ctx, ["/", "/api/items", "/api/auth/login", "/api/users/{id}"]) == ["/api/items"]


def test_writable_endpoints_fallback_without_spec():
    ctx = ScanContext(target_url="http://t", client=None, anon_client=None)
    assert _writable_endpoints(ctx, ["/", "/a", "/x/{id}"]) == ["/", "/a"]


def test_xss_json_reflection_not_flagged():
    payload = "<script>alert(1)</script>"
    def handler(request):
        return httpx.Response(200, json={"echo": payload})
    assert _run_check(check_xss, handler, ["/api/users/{id}"]) == []


def test_xss_html_reflection_flagged():
    payload = "<script>alert(1)</script>"
    def handler(request):
        return httpx.Response(200, text=f"<html>{payload}</html>",
                              headers={"content-type": "text/html; charset=utf-8"})
    findings = _run_check(check_xss, handler, ["/api/users/{id}"])
    assert len(findings) == 1 and findings[0]["type"] == "Reflected XSS"


def test_sca_is_manifest_exposure_medium():
    def handler(request):
        if request.url.path == "/requirements.txt":
            return httpx.Response(200, text="fastapi==0.115.6\n")
        return httpx.Response(404)
    findings = _run_check(check_sca, handler, [])
    assert len(findings) == 1
    assert findings[0]["level"] == "MEDIUM"
    assert findings[0]["type"] == "Dependency Manifest Exposed"


def test_idor_auth_skips_public_root():
    def handler(request):
        return httpx.Response(200, json={"status": "ok"})
    assert _run_check(check_idor_auth, handler, ["/"]) == []


def test_idor_auth_medium_without_spec_security():
    def handler(request):
        return httpx.Response(200, json={"secret": "x"})
    findings = _run_check(check_idor_auth, handler, ["/api/system/keys"])
    assert len(findings) == 1 and findings[0]["level"] == "MEDIUM"


def test_idor_auth_critical_when_spec_requires_security():
    spec = {"paths": {"/api/private": {"get": {"security": [{"bearer": []}]}}}}
    def handler(request):
        return httpx.Response(200, json={"secret": "x"})
    findings = _run_check(check_idor_auth, handler, ["/api/private"], spec=spec)
    assert len(findings) == 1 and findings[0]["level"] == "CRITICAL"


def test_csrf_skips_get_only_root_and_tests_real_post():
    spec = {"paths": {"/": {"get": {}}, "/api/items": {"post": {}}}}
    def handler(request):
        if request.method == "POST" and request.url.path == "/api/items":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(405)
    findings = _run_check(check_csrf, handler, ["/", "/api/items"], spec=spec)
    assert len(findings) == 1 and findings[0]["endpoint"] == "/api/items"


def test_security_headers_no_deprecated_xss_protection():
    def handler(request):
        return httpx.Response(200, text="ok", headers={
            "x-frame-options": "DENY", "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000"})
    assert _run_check(check_security_headers, handler, []) == []
