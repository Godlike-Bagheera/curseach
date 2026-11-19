"""Роуты сканера: валидация /scan, status, cancel, отчёты json/csv/xlsx."""

import time

import pytest
from fastapi.testclient import TestClient

import web_app
from scanner.tasks import ScanTask, tasks


@pytest.fixture()
def client():
    c = TestClient(web_app.app)
    c.post("/login", data={"username": "admin", "password": "admin"})
    return c


@pytest.fixture()
def done_task():
    t = ScanTask("http://127.0.0.1:8000", mode="quick")
    t.status = "completed"
    t.finished_at = time.time()
    t.scan_results = [
        {
            "level": "HIGH",
            "type": "SQL Injection",
            "endpoint": "/x",
            "desc": "d",
            "details": {"plain": "p", "recommendation": "r"},
        },
    ]
    t.high_count = 1
    t.score = 90
    tasks[t.id] = t
    yield t
    tasks.pop(t.id, None)


def test_available_checks(client):
    r = client.get("/available-checks")
    assert r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) >= 20


def test_scan_validation(client):
    assert client.post("/scan", json={"url": "http://t", "mode": "bad"}).status_code == 400
    assert client.post("/scan", json={"url": "http://t", "mode": "custom", "checks": []}).status_code == 400
    assert client.post("/scan", json={"url": "not-a-url", "mode": "quick"}).status_code == 400


def test_status(client, done_task):
    assert client.get("/status/nope").status_code == 404
    r = client.get(f"/status/{done_task.id}")
    assert r.status_code == 200 and r.json()["status"] == "completed"
    assert "requests_used" in r.json()


def test_cancel(client, done_task):
    assert client.post("/scan/nope/cancel").status_code == 404
    assert client.post(f"/scan/{done_task.id}/cancel").status_code == 400
    run = ScanTask("http://t", mode="quick")
    run.status = "running"
    tasks[run.id] = run
    try:
        r = client.post(f"/scan/{run.id}/cancel")
        assert r.status_code == 200 and r.json()["status"] == "cancelling"
        assert run.cancel_event.is_set()
    finally:
        tasks.pop(run.id, None)


def test_report_json(client, done_task):
    assert client.get("/report/json/nope").status_code == 404
    pend = ScanTask("http://t", mode="quick")
    tasks[pend.id] = pend
    try:
        assert client.get(f"/report/json/{pend.id}").status_code == 400
    finally:
        tasks.pop(pend.id, None)
    r = client.get(f"/report/json/{done_task.id}")
    assert r.status_code == 200 and r.json()["metrics"]["high"] == 1


def test_report_csv(client, done_task):
    assert client.get("/report/csv/nope").status_code == 404
    r = client.get(f"/report/csv/{done_task.id}")
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]


def test_report_xlsx(client, done_task):
    assert client.get("/report/xlsx/nope").status_code == 404
    r = client.get(f"/report/xlsx/{done_task.id}")
    assert r.status_code == 200
