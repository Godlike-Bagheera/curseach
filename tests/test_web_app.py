"""Тести безопасности веб-приложения сканера."""
import pytest
from fastapi.testclient import TestClient

import web_app


@pytest.fixture()
def client():
    return TestClient(web_app.app)


def _login(client, user="admin", password="admin"):
    r = client.post("/login", data={"username": user, "password": password}, follow_redirects=False)
    return r


def test_login_wrong_password(client):
    r = _login(client, "admin", "wrong")
    assert r.status_code == 401


def test_login_success_sets_httponly_cookie(client):
    r = _login(client)
    assert r.status_code == 303
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "session_id=" in cookie


def test_index_redirects_anonymous(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_forbidden_origin_blocked(client):
    r = client.post("/scan", json={"url": "http://localhost:8000"},
                    headers={"Origin": "https://evil.example.com"})
    assert r.status_code == 403


def test_ssrf_metadata_ip_blocked(client):
    _login(client)
    err = web_app._validate_target_url("http://169.254.169.254/latest/meta-data/")
    assert err is not None and "SSRF" in err


def test_ssrf_localhost_allowed_by_default(client):
    # учебный стенд живёт на localhost — он должен быть разрешён
    assert web_app._validate_target_url("http://127.0.0.1:8000") is None


def test_invalid_urls(client):
    assert web_app._validate_target_url("") is not None
    assert web_app._validate_target_url("ftp://x") is not None
    assert web_app._validate_target_url("http://") is not None


def test_scan_requires_auth(client):
    r = client.get("/history")
    assert r.status_code == 401


def test_score_calculation():
    assert web_app.calculate_score(0, 0, 0, 0) == 100
    assert web_app.calculate_score(5, 0, 0, 0) == 0
    assert web_app.calculate_score(1, 1, 1, 1) == 100 - 37


def test_sarif_export_shape():
    sarif = web_app._results_to_sarif(
        "http://t", "2026-01-01",
        [{"level": "CRITICAL", "type": "SQLi", "desc": "d"}],
    )
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "SQLi"
    assert run["results"][0]["level"] == "error"
