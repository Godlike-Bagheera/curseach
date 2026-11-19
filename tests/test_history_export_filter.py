"""Экспорт истории уважает фильтр дат (?from=&to=)."""

from fastapi.testclient import TestClient

import database
import web_app
from scanner.routes.history import _filter_scans_by_date


def test_filter_scans_by_date():
    scans = [
        {"scan_date": "2026-11-01T10:00:00"},
        {"scan_date": "2026-11-10T10:00:00"},
        {"scan_date": "2026-11-20T10:00:00"},
    ]
    assert len(_filter_scans_by_date(scans, None, None)) == 3
    mid = _filter_scans_by_date(scans, "2026-11-05", "2026-11-15")
    assert [s["scan_date"][:10] for s in mid] == ["2026-11-10"]
    assert _filter_scans_by_date(scans, "2026-11-20", None) == [scans[2]]
    assert _filter_scans_by_date(scans, None, "2026-11-01") == [scans[0]]
    assert _filter_scans_by_date(scans, "2030-01-01", None) == []


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)


def test_export_xlsx_requires_auth():
    client = TestClient(web_app.app)
    r = client.get("/history/export.xlsx?from=2026-01-01&to=2026-12-31")
    assert r.status_code == 401


def test_export_xlsx_with_range():
    database.save_scan("http://127.0.0.1:8000", 1, 0, 0, 0, [])
    client = TestClient(web_app.app)
    assert _login(client).status_code == 303
    ok = client.get("/history/export.xlsx?from=2000-01-01&to=2999-12-31")
    assert ok.status_code == 200
    assert ok.headers["content-type"].startswith("application/vnd.openxmlformats")
    empty = client.get("/history/export.xlsx?from=2999-01-01")
    assert empty.status_code == 200
