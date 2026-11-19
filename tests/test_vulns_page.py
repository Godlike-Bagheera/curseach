"""Справочник уязвимостей доступен гостю: EN/RU/смысл + реестр всех проверок."""
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


def test_vulns_page_has_full_registry():
    client = TestClient(web_app.app)
    body = client.get("/vulns").text
    assert "Все проверки сканера" in body
    assert "check_cors" in body and "check_hidden_paths" in body
    assert "check_graphql_introspection" in body
    assert 'id="sql-injection"' in body
    assert "cwe-89" in body


def test_vulns_search_script_is_external():
    client = TestClient(web_app.app)
    body = client.get("/vulns").text
    assert '/static/vulns.js' in body
    js = client.get("/static/vulns.js")
    assert js.status_code == 200
