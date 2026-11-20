"""Auth-профили: bearer/form/apikey/refresh (MockTransport) + БД."""

import asyncio
import json

import httpx

from scanner.tasks import AccountConfig, _attach_refresh, authenticate_account, login_and_get_token, refresh_auth

T = "http://127.0.0.1:8000"


def test_bearer_login():
    def handler(req):
        assert req.url.path == "/api/auth/login"
        assert json.loads(req.content) == {"username": "u", "password": "p"}
        return httpx.Response(200, json={"token": "tok123"})

    st = asyncio.run(
        authenticate_account(T, AccountConfig(username="u", password="p"), transport=httpx.MockTransport(handler))
    )
    assert st.ok and st.headers["Authorization"] == "Bearer tok123" and st.token == "tok123"


def test_apikey():
    st = asyncio.run(
        authenticate_account(T, AccountConfig(auth_type="apikey", api_key_header="X-API-Key", api_key_value="secret"))
    )
    assert st.ok and st.headers == {"X-API-Key": "secret"} and st.token is None


def test_apikey_missing():
    assert not asyncio.run(authenticate_account(T, AccountConfig(auth_type="apikey"))).ok


def test_form_login_cookies():
    def handler(req):
        assert req.url.path == "/login"
        assert b"username=u" in req.content and b"password=p" in req.content and b"csrf=abc" in req.content
        return httpx.Response(302, headers={"Set-Cookie": "session=xyz; Path=/"})

    acc = AccountConfig(auth_type="form", username="u", password="p", login_path="/login", form_fields={"csrf": "abc"})
    st = asyncio.run(authenticate_account(T, acc, transport=httpx.MockTransport(handler)))
    assert st.ok and st.cookies.get("session") == "xyz"


def test_form_login_token():
    def handler(req):
        return httpx.Response(200, json={"token": "formtok"})

    acc = AccountConfig(auth_type="form", username="u", password="p")
    st = asyncio.run(authenticate_account(T, acc, transport=httpx.MockTransport(handler)))
    assert st.ok and st.headers["Authorization"] == "Bearer formtok"


def test_refresh_new_token():
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(200, json={"token": f"tok{n['c']}"})

    acc = AccountConfig(username="u", password="p")
    t = httpx.MockTransport(handler)
    s1 = asyncio.run(refresh_auth(T, acc, transport=t))
    s2 = asyncio.run(refresh_auth(T, acc, transport=t))
    assert s1.token == "tok1" and s2.token == "tok2"


def test_refresh_hook_on_401():
    n = {"c": 0}

    def handler(req):
        if req.url.path == "/api/auth/login":
            n["c"] += 1
            return httpx.Response(200, json={"token": f"tok{n['c']}"})
        return httpx.Response(401)

    async def go():
        acc = AccountConfig(username="u", password="p")
        t = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=t)
        _attach_refresh(client, T, acc, transport=t)
        await client.get(T + "/api/me")
        await client.aclose()
        return n["c"], client.headers.get("Authorization")

    c, auth = asyncio.run(go())
    assert c == 1 and auth == "Bearer tok1"


def test_login_and_get_token_apikey_none():
    assert (
        asyncio.run(login_and_get_token(T, AccountConfig(auth_type="apikey", api_key_header="X", api_key_value="y")))
        is None
    )


def test_db_profile_roundtrip():
    import database

    database.init_db()
    pid = database.save_auth_profile("test-prof", auth_type="apikey", api_key_header="X-API-Key", api_key_value="s")
    p = database.get_auth_profile(pid)
    assert p["name"] == "test-prof" and p["auth_type"] == "apikey" and p["api_key_value"] == "s"
    acc = database.profile_to_account(p)
    assert acc["auth_type"] == "apikey" and acc["api_key_header"] == "X-API-Key"
    database.delete_auth_profile(pid)
    assert database.get_auth_profile(pid) is None
