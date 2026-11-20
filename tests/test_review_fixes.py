"""Регрессии на исправления обзора: точность детектирования и классификация."""

import asyncio

import httpx

from checks import auth, data, headers, logic, misc
from checks.base import ScanContext, _is_auth_endpoint, enrich_findings, redact_evidence


def _run(check_fn, handler, endpoints, spec=None, target="http://t", has_auth=True, anon_handler=None):
    async def runner():
        async with (
            httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c,
            httpx.AsyncClient(transport=httpx.MockTransport(anon_handler or handler)) as anon,
        ):
            ctx = ScanContext(target_url=target, client=c, anon_client=anon, has_auth=has_auth, openapi=spec)
            return await check_fn(ctx, endpoints)

    return asyncio.run(runner())


def test_bfla_emits_precise_type():
    def user(r):
        return httpx.Response(200, json={"users": [{"id": 1}], "role": "admin"})

    f = _run(auth.check_bfla, user, ["/api/admin/users"], anon_handler=lambda r: httpx.Response(401))
    assert f and all(x["type"] == "Broken Function Level Authorization" for x in f)


def test_tls_expired_via_verify_message(monkeypatch):
    monkeypatch.setattr(headers, "_tls_probe", lambda h, p: {"version": "TLSv1.3", "trusted": False, "expired": True})
    f = _run(headers.check_tls_version, lambda r: httpx.Response(200), [], target="https://t")
    assert any(x["type"] == "TLS Certificate Expired" for x in f)
    assert not any(x["type"] == "TLS Certificate Untrusted" for x in f)


def test_hidden_paths_skips_documented():
    f = _run(misc.check_hidden_paths, lambda r: httpx.Response(200, text="panel"), ["/admin"])
    assert all(x["endpoint"] != "/admin" for x in f)


def test_hidden_paths_spa_catchall_not_flagged():
    assert _run(misc.check_hidden_paths, lambda r: httpx.Response(200, text="<html>SPA</html>"), []) == []


def test_hidden_paths_real_secret_flagged():
    def handler(r):
        return httpx.Response(200, text="DB_PASSWORD=secret") if r.url.path == "/.env" else httpx.Response(404)

    assert any(x["endpoint"] == "/.env" for x in _run(misc.check_hidden_paths, handler, []))


def test_sca_html_not_manifest():
    assert _run(data.check_sca, lambda r: httpx.Response(200, text="<html><body>SPA</body></html>"), []) == []


def test_sca_valid_json_manifest():
    f = _run(data.check_sca, lambda r: httpx.Response(200, text='{"dependencies":{"lodash":"4.17.4"}}'), [])
    assert len(f) == 1 and f[0]["type"] == "Dependency Manifest Exposed"


def test_is_auth_endpoint_segments():
    assert _is_auth_endpoint("/api/auth/login") is True
    assert _is_auth_endpoint("/oauth/token") is True
    assert _is_auth_endpoint("/api/authors") is False
    assert _is_auth_endpoint("/authority") is False


def test_idor_auth_normalizes_dynamic_content():
    from checks.access import check_idor_auth

    f = _run(
        check_idor_auth,
        lambda r: httpx.Response(200, json={"data": "x", "timestamp": 1111111111}),
        ["/api/private"],
        anon_handler=lambda r: httpx.Response(200, json={"data": "x", "timestamp": 2222222222}),
    )
    assert len(f) == 1


def test_cvss_vector_severity():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert data._osv_severity({"severity": [{"type": "CVSS_V3", "score": vec}]})[0] == "CRITICAL"
    low = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    assert data._osv_severity({"severity": [{"type": "CVSS_V3", "score": low}]})[0] == "MEDIUM"


def test_rate_limiting_non200_not_flagged():
    assert _run(misc.check_rate_limiting, lambda r: httpx.Response(404), ["/"]) == []


def test_unsafe_methods_rest_put_delete_ok():
    assert (
        _run(headers.check_unsafe_methods, lambda r: httpx.Response(200, headers={"allow": "GET, PUT, DELETE"}), ["/"])
        == []
    )


def test_unsafe_methods_trace_flagged():
    assert (
        len(_run(headers.check_unsafe_methods, lambda r: httpx.Response(200, headers={"allow": "GET, TRACE"}), ["/"]))
        == 1
    )


def test_evidence_redaction():
    out = redact_evidence({"request_body": '{"password":"hunter2"}', "response_body": "AKIAIOSFODNN7EXAMPLE"})
    assert "hunter2" not in out["request_body"] and "AKIAIOSFODNN7EXAMPLE" not in out["response_body"]


def test_enrich_normalizes_method_param():
    fs = [{"type": "SQL Injection", "endpoint": "/x", "level": "CRITICAL", "desc": "d"}]
    enrich_findings(fs)
    assert fs[0]["method"] == "" and fs[0]["param"] == ""


def test_mass_assignment_readback_via_get():
    spec = {"paths": {"/api/items": {"post": {}}}}

    def handler(r):
        return (
            httpx.Response(201, json={"id": 7})
            if r.method == "POST"
            else httpx.Response(200, json={"id": 7, "is_admin": True})
        )

    f = _run(logic.check_mass_assignment, handler, ["/api/items"], spec=spec)
    assert len(f) == 1 and f[0]["type"] == "Mass Assignment"
