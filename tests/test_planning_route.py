"""Роуты /projects, /schedules, /history/trend (CI: TestClient)."""

import pytest
from fastapi.testclient import TestClient

import web_app


@pytest.fixture()
def authed_client():
    client = TestClient(web_app.app)
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    return client


def test_trend_route_not_shadowed(authed_client):
    r = authed_client.get("/history/trend")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_projects_crud(authed_client):
    r = authed_client.post("/projects", json={"name": "route-proj"})
    assert r.status_code == 200
    pid = r.json()["id"]
    assert any(p["id"] == pid for p in authed_client.get("/projects").json())
    assert authed_client.delete(f"/projects/{pid}").status_code == 200


def test_schedules_crud(authed_client):
    r = authed_client.post("/schedules", json={"target_url": "http://127.0.0.1:8000", "interval": 30})
    assert r.status_code == 200
    sid = r.json()["id"]
    assert any(s["id"] == sid for s in authed_client.get("/schedules").json())
    assert authed_client.delete(f"/schedules/{sid}").status_code == 200


def test_schedule_bad_url(authed_client):
    r = authed_client.post("/schedules", json={"target_url": "ftp://bad", "interval": 30})
    assert r.status_code == 400
