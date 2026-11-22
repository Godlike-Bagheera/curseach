"""Серверная фильтрация и пагинация истории (database.query_scans + /history)."""

from fastapi.testclient import TestClient

import database
import web_app


def test_query_scans_filters(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "t.db"))
    database.init_db()
    database.save_scan("http://a.example", 1, 0, 0, 0, [])
    database.save_scan("http://b.example", 0, 1, 0, 0, [])
    items, total = database.query_scans(target="a.example")
    assert total == 1 and items[0]["target_url"] == "http://a.example"
    items, total = database.query_scans(limit=1, offset=0)
    assert total == 2 and len(items) == 1
    items, total = database.query_scans(date_from="2999-01-01")
    assert total == 0 and items == []


def test_history_route_params():
    database.save_scan("http://route.example", 0, 0, 1, 0, [])
    client = TestClient(web_app.app)
    assert client.get("/history").status_code == 401
    client.post("/login", data={"username": "admin", "password": "admin"})
    r = client.get("/history?target=route.example&limit=5&offset=0")
    assert r.status_code == 200
    assert "x-total-count" in r.headers
    assert any(s["target_url"] == "http://route.example" for s in r.json())
