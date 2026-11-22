"""Юнит-тесты SSRF-проверки на httpx.MockTransport — без реальной сети."""

import asyncio

import httpx

from checks.base import ScanContext
from checks.ssrf import check_ssrf

_SPEC = {
    "paths": {
        "/api/fetch-url": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"type": "object", "properties": {"url": {"type": "string"}}}}
                    }
                }
            }
        }
    }
}


def _run(handler):
    async def runner():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client, httpx.AsyncClient(transport=transport) as anon:
            ctx = ScanContext(target_url="http://t", client=client, anon_client=anon, openapi=_SPEC)
            return await check_ssrf(ctx, ["/api/fetch-url"])

    return asyncio.run(runner())


def test_ssrf_metadata_leak_flagged():
    def handler(request):
        if "169.254.169.254" in request.content.decode():
            return httpx.Response(200, json={"data": {"ami-id": "ami-123", "instance-id": "i-1"}})
        return httpx.Response(200, json={"data": {"title": "Example Domain"}})

    findings = _run(handler)
    assert len(findings) == 1
    assert findings[0]["type"] == "Server-Side Request Forgery"
    assert findings[0]["level"] == "HIGH"
    assert findings[0]["confidence"] == "high"


def test_ssrf_internal_service_flagged():
    def handler(request):
        if "127.0.0.1" in request.content.decode() or "localhost" in request.content.decode():
            return httpx.Response(200, json={"data": {"service": "internal-admin-panel"}})
        return httpx.Response(200, json={"data": {"title": "Example Domain"}})

    findings = _run(handler)
    assert len(findings) == 1 and findings[0]["confidence"] == "medium"


def test_ssrf_validated_url_not_flagged():
    def handler(request):
        return httpx.Response(200, json={"data": {"title": "Example Domain"}})

    assert _run(handler) == []
