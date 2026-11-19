"""Справочник уязвимостей доступен гостю и содержит EN/RU/смысл."""
from fastapi.testclient import TestClient
import web_app


def test_vulns_page_guest_ok():
    client = TestClient(web_app.app)
    r = client.get("/vulns")
    assert r.status_code == 200
    body = r.text
    assert "SQL Injection" in body and "SQL-инъекция" in body
    assert "CWE-89" in body and "SSRF" in body
    assert "Как защититься" in body
