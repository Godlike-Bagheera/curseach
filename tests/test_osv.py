"""Юнит-тесты OSV SCA: парсинг манифестов, severity, запросы к OSV."""

import asyncio

import httpx

from checks.base import ScanContext
from checks.data import (
    _fixed_versions,
    _osv_lookup,
    _osv_severity,
    check_osv_sca,
    parse_package_json,
    parse_requirements,
)


def test_parse_requirements():
    txt = "flask==0.12\n# comment\n-r other.txt\nrequests==2.19.1 ; python_version<'3'\nnoversion\n"
    assert parse_requirements(txt) == [("flask", "0.12"), ("requests", "2.19.1")]


def test_parse_package_json():
    txt = '{"dependencies":{"lodash":"^4.17.4","a":"*","b":"git+https://x"},"devDependencies":{"jest":"29.0.0"}}'
    # Диапазоны (^4.17.4) не являются точным пином — пропускаются (только exact).
    assert parse_package_json(txt) == [("jest", "29.0.0")]
    assert parse_package_json("not json") == []


def test_severity_mapping():
    assert _osv_severity({"database_specific": {"severity": "MODERATE"}})[0] == "MEDIUM"
    assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": "9.8"}]})[0] == "CRITICAL"
    assert _osv_severity({})[0] == "HIGH"


def test_fixed_versions():
    doc = {
        "affected": [
            {
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}],
            }
        ]
    }
    assert _fixed_versions(doc, "flask", "PyPI") == ["0.12.3"]


def _osv_handler(request):
    if request.url.path.endswith("/querybatch"):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-xxxx"}]}, {}]})
    if "/vulns/GHSA-xxxx" in request.url.path:
        return httpx.Response(
            200,
            json={
                "id": "GHSA-xxxx",
                "aliases": ["CVE-2018-1000"],
                "summary": "bad flask",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {"package": {"name": "flask", "ecosystem": "PyPI"}, "ranges": [{"events": [{"fixed": "0.12.3"}]}]}
                ],
            },
        )
    return httpx.Response(404)


def test_osv_lookup_and_check():
    def target_handler(request):
        if request.url.path == "/requirements.txt":
            return httpx.Response(200, text="flask==0.12\n")
        return httpx.Response(404)

    async def run():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(target_handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(_osv_handler)) as osv,
        ):
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c)
            pairs = await _osv_lookup([("flask", "0.12", "PyPI")], client=osv)
            assert len(pairs) == 1 and pairs[0][1]["id"] == "GHSA-xxxx"
            fs = await check_osv_sca(ctx, [], osv_client=osv)
            assert len(fs) == 1
            assert fs[0]["level"] == "HIGH" and fs[0]["type"] == "Vulnerable Dependency (OSV)"
            assert fs[0]["evidence"]["fixed"] == ["0.12.3"]

    asyncio.run(run())


def test_osv_network_failure_graceful():
    def boom(request):
        raise httpx.ConnectError("no network")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as osv:
            assert await _osv_lookup([("flask", "0.12", "PyPI")], client=osv) == []

    asyncio.run(run())
