"""CSP: script-src без 'unsafe-inline', per-request nonce в заголовке и inline-скриптах."""

import re

from fastapi.testclient import TestClient

import database
import web_app


def test_csp_nonce_no_unsafe_inline(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "c.db"))
    database.init_db()
    database.save_scan(
        "http://t.example",
        0,
        1,
        0,
        0,
        [
            {
                "level": "HIGH",
                "type": "SQL Injection",
                "endpoint": "/x",
                "desc": "d",
                "details": {"plain": "p", "recommendation": "r"},
            },
        ],
    )
    client = TestClient(web_app.app)
    r = client.get("/vulns")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self' 'nonce-" in csp
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    nonce1 = re.search(r"nonce-([A-Za-z0-9_\-]+)", csp).group(1)

    client.post("/login", data={"username": "admin", "password": "admin"})
    chart = client.get("/history/1/chart")
    assert chart.status_code == 200
    csp2 = chart.headers["content-security-policy"]
    nonce2 = re.search(r"nonce-([A-Za-z0-9_\-]+)", csp2).group(1)
    assert nonce1 != nonce2  # nonce уникальный на каждый запрос
    assert f'nonce="{nonce2}"' in chart.text  # inline Chart.js несёт тот же nonce


def test_security_headers_present_on_scanner():
    client = TestClient(web_app.app)
    r = client.get("/login")
    assert r.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in r.headers["permissions-policy"]
    csp = r.headers["content-security-policy"]
    assert "form-action 'self'" in csp


def test_logout_requires_post():
    client = TestClient(web_app.app)
    client.post("/login", data={"username": "admin", "password": "admin"})
    # GET больше не разлогинивает (защита от logout-CSRF через ссылку/картинку)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", follow_redirects=False).status_code == 303
