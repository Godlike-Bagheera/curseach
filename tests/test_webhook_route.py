"""Роут /scan: валидация webhook_url (CI: TestClient)."""

import pytest
from fastapi.testclient import TestClient

import web_app


@pytest.fixture()
def authed_client():
    client = TestClient(web_app.app)
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    return client


def test_scan_rejects_bad_webhook(authed_client):
    r = authed_client.post("/scan", json={"url": "http://127.0.0.1:8000", "mode": "quick", "webhook_url": "ftp://bad"})
    assert r.status_code == 400
    assert "webhook" in r.json()["detail"]
