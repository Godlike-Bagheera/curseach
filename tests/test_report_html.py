"""Регрессия: /report/html/{task_id} рендерится, а не падает в 422/500."""
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


def test_report_html_renders_for_completed_task(authed_client):
    task = ScanTask("http://127.0.0.1:8000", mode="quick")
    task.status = "completed"
    task.finished_at = time.time()
    task.scan_results = [{"level": "HIGH", "type": "SQL Injection", "endpoint": "/api/users/{user_id}",
                          "desc": "test", "details": {"plain": "p", "recommendation": "r"}}]
    task.high_count = 1
    task.score = 90
    tasks[task.id] = task
    try:
        r = authed_client.get(f"/report/html/{task.id}")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "127.0.0.1:8000" in r.text
    finally:
        tasks.pop(task.id, None)


def test_report_html_requires_auth():
    client = TestClient(web_app.app)
    r = client.get("/report/html/whatever", follow_redirects=False)
    assert r.status_code in (303, 401, 403)
