"""Юнит-тесты поверхностей атаки из OpenAPI."""
import asyncio
import httpx
from checks.base import ScanContext
from checks.surface import build_surfaces, sample_from_schema, build_url_query_body, probe

SPEC = {
    "paths": {
        "/a/{id}": {
            "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
            "get": {},
            "post": {
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}},
            },
        },
        "/static": {"get": {}},
    },
    "components": {"schemas": {"Item": {
        "type": "object",
        "properties": {"name": {"type": "string"}, "count": {"type": "integer"}, "tag": {"enum": ["x", "y"]}},
        "required": ["name"],
    }}},
}

def _ctx(spec=None):
    return ScanContext(target_url="http://t", client=None, anon_client=None, openapi=spec)

def test_sample_schema_ref_enum_types():
    s = sample_from_schema({"$ref": "#/components/schemas/Item"}, SPEC)
    assert s["name"] == "test" and s["count"] == 1 and s["tag"] == "x"
    assert sample_from_schema({"type": "array", "items": {"type": "boolean"}}, {}) == [True]
    assert sample_from_schema({"type": "number", "default": 2.5}, {}) == 2.5
    assert sample_from_schema({"example": "ex"}, {}) == "ex"

def test_build_surfaces_methods_params_body():
    surfs = build_surfaces(_ctx(SPEC), ["/a/{id}", "/static"])
    gets = [s for s in surfs if s.method == "get" and s.path == "/a/{id}"]
    posts = [s for s in surfs if s.method == "post"]
    assert gets and ("path", "id") in gets[0].injectable
    assert posts and posts[0].body["name"] == "test"
    assert ("query", "q") in posts[0].injectable and ("body", "name") in posts[0].injectable

def test_build_surfaces_fallback_without_spec():
    surfs = build_surfaces(_ctx(None), ["/x/{id}", "/y"])
    assert len(surfs) == 2 and surfs[0].method == "get"
    assert surfs[0].path_params == {"id": "1"} and surfs[1].injectable == []

def test_build_url_query_body_overrides():
    s = [x for x in build_surfaces(_ctx(SPEC)) if x.method == "post"][0]
    path, query, body = build_url_query_body(s, path_over={"id": "7"}, query_over={"q": "a b"}, body_over={"name": "pwn"})
    assert path == "/a/7" and query["q"] == "a b" and body["name"] == "pwn" and body["count"] == 1

def test_probe_sends_method_query_body():
    seen = {}
    def handler(request):
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"ok": True})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c, openapi=SPEC)
            s = [x for x in build_surfaces(ctx) if x.method == "post"][0]
            r = await probe(ctx, s, path_over={"id": "9"}, body_over={"name": "zz"})
            assert r.status_code == 200
    asyncio.run(run())
    assert seen["method"] == "POST" and "/a/9" in seen["url"] and "zz" in seen["body"]
