"""JWT weak-secret: подбор HMAC-секрета из wordlist."""

import asyncio
import base64
import hashlib
import hmac

import httpx

from checks.auth import check_jwt_weak_secret
from checks.base import ScanContext


def test_jwt_weak_secret_flagged():
    def handler(r):
        auth = r.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return httpx.Response(401)
        parts = auth[7:].split(".")
        if len(parts) != 3:
            return httpx.Response(401)
        h, p, sig = parts
        expected = (
            base64.urlsafe_b64encode(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest())
            .rstrip(b"=")
            .decode()
        )
        return httpx.Response(200 if hmac.compare_digest(sig, expected) else 401, json={"ok": True})

    async def runner():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(
                target_url="http://t", client=c, anon_client=c, openapi={"paths": {"/api/jwt-weak/{id}": {"get": {}}}}
            )
            return await check_jwt_weak_secret(ctx, ["/api/jwt-weak/{id}"])

    f = asyncio.run(runner())
    assert len(f) == 1 and f[0]["type"] == "JWT Weak Secret" and "secret" in f[0]["desc"]
