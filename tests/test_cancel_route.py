"""Роут отмены скана и /healthz."""
import time

import pytest
from fastapi.testclient import TestClient

import web_app
from scanner.tasks import ScanTask, tasks


@pytest.fixture()
def authed_client():
    client = TestClient(web_app.app)
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    return client


def test_healthz_no_auth():
    client = TestClient(web_app.app)
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_cancel_running_scan(authed_client):
    task = ScanTask("http://127.0.0.1:8000", mode="quick")
    task.status = "running"
    tasks[task.id] = task
    try:
        r = authed_client.post(f"/scan/{task.id}/cancel")
        assert r.status_code == 200
        assert task.cancel_event.is_set()
    finally:
        tasks.pop(task.id, None)


def test_cancel_finished_scan_400(authed_client):
    task = ScanTask("http://127.0.0.1:8000", mode="quick")
    task.status = "completed"
    task.finished_at = time.time()
    tasks[task.id] = task
    try:
        r = authed_client.post(f"/scan/{task.id}/cancel")
        assert r.status_code == 400
    finally:
        tasks.pop(task.id, None)


def test_cancel_missing_scan_404(authed_client):
    r = authed_client.post("/scan/nonexistent/cancel")
    assert r.status_code == 404


def test_cancel_requires_auth():
    client = TestClient(web_app.app)
    r = client.post("/scan/whatever/cancel")
    assert r.status_code in (303, 401, 403)
