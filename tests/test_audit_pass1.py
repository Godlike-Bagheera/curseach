"""Регрессии аудита (проход 1): профили, расписания, webhook, отчёты, WS, GC, cookie."""

import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

import database
import web_app
from checks.base import ScanContext
from checks.cookies import check_cookie_flags
from scanner.reporting import scan_csv_bytes, scan_json_payload
from scanner.scheduler import run_due_schedules
from scanner.tasks import ScanTask, _gc_sweep, tasks
from scanner.webhook import build_summary


@pytest.fixture()
def authed_client():
    client = TestClient(web_app.app)
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    return client


def test_profile_form_fields_roundtrip():
    database.init_db()
    pid = database.save_auth_profile(
        "audit-form-prof", auth_type="form", username="u", password="p",
        form_fields={"csrf": "abc"}, login_path="/login",
    )
    try:
        p = database.get_auth_profile(pid)
        assert p["form_fields"] == {"csrf": "abc"}
        acc = database.profile_to_account(p)
        assert acc["form_fields"] == {"csrf": "abc"}
        assert acc["login_path"] == "/login"
    finally:
        database.delete_auth_profile(pid)


def test_scan_task_normalizes_trailing_slash():
    assert ScanTask("http://t:8000/").target_url == "http://t:8000"
    assert ScanTask("http://t:8000").target_url == "http://t:8000"


def test_build_summary_status_override():
    t = ScanTask("http://t")
    assert build_summary(t)["status"] == "pending"
    assert build_summary(t, status="completed")["status"] == "completed"


def test_ws_cancelled_task_gets_complete(authed_client):
    task = ScanTask("http://t", mode="quick")
    task.status = "cancelled"
    task.finished_at = time.time()
    tasks[task.id] = task
    try:
        with authed_client.websocket_connect(f"/ws/scan/{task.id}") as ws:
            init = ws.receive_json()
            assert init["type"] == "init"
            done = ws.receive_json()
            assert done == {"type": "complete", "status": "cancelled"}
    finally:
        tasks.pop(task.id, None)


def test_scheduler_sets_task_loop(monkeypatch):
    database.init_db()
    sid = database.create_schedule("http://audit-sched", interval=10)
    captured = []
    import scanner.scheduler as sch

    monkeypatch.setattr(sch, "run_scan_in_thread", lambda task: captured.append(task))
    try:
        asyncio.run(run_due_schedules(time.time()))
        assert captured and captured[0].loop is not None
    finally:
        database.delete_schedule(sid)


def test_schedule_custom_mode_rejected(authed_client):
    r = authed_client.post(
        "/schedules", json={"target_url": "http://127.0.0.1:8000", "mode": "custom", "interval": 30}
    )
    assert r.status_code == 400


def test_schedule_bad_webhook_rejected(authed_client):
    r = authed_client.post(
        "/schedules", json={"target_url": "http://127.0.0.1:8000", "interval": 30, "webhook_url": "ftp://bad"}
    )
    assert r.status_code == 400


def test_history_exports_use_real_mode():
    scan = {
        "id": 1, "target_url": "http://t", "scan_date": "2026-01-01T00:00:00+00:00",
        "critical": 0, "high": 0, "medium": 0, "low": 0, "results": [], "mode": "quick",
    }
    assert json.loads(scan_json_payload(scan))["mode"] == "quick"
    assert "БЫСТРАЯ ПРОВЕРКА" in scan_csv_bytes(scan).decode("utf-8-sig")


def test_cookie_flag_not_masked_by_name():
    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": "secure_session=1; Path=/"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c)
            return await check_cookie_flags(ctx, [])

    f = asyncio.run(go())
    assert f and "нет Secure" in f[0]["desc"]


def test_gc_sweep_prunes_login_buckets():
    from scanner import security

    security._login_attempts["audit-old-ip"] = [time.time() - 10 * 60]
    security._login_attempts["audit-fresh-ip"] = [time.time()]
    _gc_sweep(time.time())
    assert "audit-old-ip" not in security._login_attempts
    assert "audit-fresh-ip" in security._login_attempts
    security._login_attempts.pop("audit-fresh-ip", None)
