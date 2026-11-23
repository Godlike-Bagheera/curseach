"""run_due_schedules регистрирует ScanTask в tasks: чистится _gc_sweep, отменяема."""

import scanner.scheduler as scheduler
from scanner.tasks import tasks


def test_due_schedule_registers_task(monkeypatch):
    created = {}

    class FakeTask:
        id = "sched-task-1"

        def __init__(self, *a, **kw):
            created["args"] = a
            created["kwargs"] = kw

    def fake_due(now):
        return [{"id": 7, "target_url": "http://t", "mode": "quick", "profile_id": None, "webhook_url": None}]

    called = {}

    def fake_run_in_thread(task):
        called["task"] = task

    monkeypatch.setattr(scheduler, "ScanTask", FakeTask)
    monkeypatch.setattr(scheduler, "run_scan_in_thread", fake_run_in_thread)
    monkeypatch.setattr(scheduler.database, "due_schedules", fake_due)
    monkeypatch.setattr(scheduler.database, "mark_schedule_run", lambda *a: None)

    started = asyncio_run(scheduler.run_due_schedules())

    assert started == [7]
    assert tasks.get("sched-task-1") is not None
    # Чистим за тестом: словарь глобальный.
    tasks.pop("sched-task-1", None)


def asyncio_run(coro):
    import asyncio

    return asyncio.new_event_loop().run_until_complete(coro)
