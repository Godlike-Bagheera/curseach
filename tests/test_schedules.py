"""Расписания/проекты/тренд: due-выбор, агрегация, фильтр по проекту (ROADMAP 7)."""

import asyncio
import time

import database
from scanner.scheduler import _account_from_profile, run_due_schedules


def test_project_crud():
    database.init_db()
    pid = database.create_project("proj-a")
    assert any(p["name"] == "proj-a" for p in database.list_projects())
    database.delete_project(pid)
    assert not any(p["id"] == pid for p in database.list_projects())


def test_trend_project_filter_and_aggregation():
    database.init_db()
    pid = database.create_project("trend-proj")
    database.save_scan("http://trend-a", 1, 0, 0, 0, [], project_id=pid)
    database.save_scan("http://trend-a", 0, 1, 0, 0, [], project_id=pid)
    database.save_scan("http://trend-other", 5, 0, 0, 0, [])
    tr = database.get_trend(project_id=pid)
    assert tr, "тренд по проекту пуст"
    day = tr[-1]
    assert day["critical"] == 1 and day["high"] == 1
    assert day["score"] == 70  # 100 - 20 - 10
    assert all(d["critical"] < 5 for d in tr)  # чужой скан (critical=5) не попал
    database.delete_project(pid)


def test_due_selection():
    database.init_db()
    now = time.time()
    sid = database.create_schedule("http://due-x", interval=10)
    assert any(s["id"] == sid for s in database.due_schedules(now))  # last_run NULL -> due
    database.mark_schedule_run(sid, now)
    assert not any(s["id"] == sid for s in database.due_schedules(now + 5 * 60))
    assert any(s["id"] == sid for s in database.due_schedules(now + 11 * 60))
    database.delete_schedule(sid)


def test_disabled_not_due():
    database.init_db()
    sid = database.create_schedule("http://due-y", interval=10, enabled=False)
    assert not any(s["id"] == sid for s in database.due_schedules(time.time()))
    database.delete_schedule(sid)


def test_run_due_schedules_with_profile(monkeypatch):
    database.init_db()
    prof = database.save_auth_profile("sched-prof", auth_type="apikey", api_key_header="X-API-Key", api_key_value="s")
    sid = database.create_schedule("http://due-z", interval=10, profile_id=prof)
    captured = []
    import scanner.scheduler as sch

    monkeypatch.setattr(sch, "run_scan_in_thread", lambda task: captured.append(task))
    ids = asyncio.run(run_due_schedules(time.time()))
    assert sid in ids and len(captured) == 1
    assert captured[0].account1 is not None and captured[0].account1.auth_type == "apikey"
    assert _account_from_profile(prof).api_key_header == "X-API-Key"
    database.delete_schedule(sid)
    database.delete_auth_profile(prof)
