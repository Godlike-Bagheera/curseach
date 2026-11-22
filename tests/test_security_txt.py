"""security.txt (RFC 9116)."""

import asyncio

import httpx

from checks.base import ScanContext
from checks.misc import check_security_txt


def _run(handler):
    async def runner():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c)
            return await check_security_txt(ctx, [])

    return asyncio.run(runner())


def test_security_txt_missing():
    f = _run(lambda r: httpx.Response(404))
    assert len(f) == 1 and f[0]["type"] == "Missing security.txt"


def test_security_txt_present():
    def handler(r):
        if r.url.path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:security@example.com\nExpires: 2027-01-01")
        return httpx.Response(404)

    assert _run(handler) == []
