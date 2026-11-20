"""Discovery без OpenAPI: robots.txt / sitemap.xml / common-paths."""

import asyncio

import httpx

from checks.base import ScanContext
from checks.discovery import _path_from_url, discover_endpoints


def test_path_from_url():
    assert _path_from_url("/admin/") == "/admin"
    assert _path_from_url("https://x.example/a/b?c=1") == "/a/b"
    assert _path_from_url("relative") is None


def test_discovery_robots_sitemap_common():
    def handler(r):
        p = r.url.path
        if p == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /secret\nSitemap: https://t/sitemap.xml")
        if p == "/sitemap.xml":
            return httpx.Response(200, text="<urlset><url><loc>https://t/page-one</loc></url></urlset>")
        if p in ("/admin", "/api"):
            return httpx.Response(200, text="ok")
        return httpx.Response(404)

    async def runner():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c)
            return await discover_endpoints(ctx)

    found = asyncio.run(runner())
    assert "/secret" in found and "/page-one" in found and "/admin" in found and "/api" in found
    assert "/nonexistent" not in found
