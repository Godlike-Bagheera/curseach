"""Diff двух сканов: новые/исправленные находки + страница сравнения."""

from fastapi.testclient import TestClient

import database
import web_app


def test_diff_added_fixed(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "d.db"))
    database.init_db()
    f_sql = {
        "type": "SQL Injection",
        "endpoint": "/api/users",
        "method": "GET",
        "param": "id",
        "level": "HIGH",
        "desc": "s",
    }
    f_xss = {
        "type": "Reflected XSS",
        "endpoint": "/api/search",
        "method": "GET",
        "param": "q",
        "level": "MEDIUM",
        "desc": "x",
    }
    database.save_scan("http://t.example", 0, 1, 0, 0, [f_sql])
    database.save_scan("http://t.example", 0, 0, 1, 0, [f_xss])
    client = TestClient(web_app.app)
    assert client.get("/history/diff?a=1&b=2").status_code == 401
    client.post("/login", data={"username": "admin", "password": "admin"})
    r = client.get("/history/diff?a=1&b=2")
    assert r.status_code == 200
    d = r.json()
    assert d["added_count"] == 1 and d["fixed_count"] == 1 and d["unchanged"] == 0
    assert d["added"][0]["type"] == "Reflected XSS"
    assert d["fixed"][0]["type"] == "SQL Injection"
    assert d["same_target"] is True
    assert client.get("/history/diff?a=1&b=1").status_code == 400
    assert client.get("/history/diff?a=1&b=999").status_code == 404
    v = client.get("/history/diff/view?a=1&b=2")
    assert v.status_code == 200 and "ИСПРАВЛЕНО" in v.text.upper()
