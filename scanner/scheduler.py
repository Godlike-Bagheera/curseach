"""Фоновый планировщик повторных сканов (ROADMAP: операционные фичи).

Тик раз в минуту: запускает due-расписания (enabled, last_run + interval <= now).
Ошибка запуска одного расписания не останавливает планировщик.
"""

import asyncio
import time

import database

from .tasks import AccountConfig, ScanTask, run_scan_in_thread, tasks

SCHEDULER_TICK_SECONDS = 60


def _account_from_profile(profile_id) -> AccountConfig | None:
    if not profile_id:
        return None
    p = database.get_auth_profile(profile_id)
    if not p:
        return None
    return AccountConfig(**database.profile_to_account(p))


async def run_due_schedules(now: float | None = None) -> list[int]:
    """Запускает due-сканы. Возвращает id запущенных расписаний (для тестов)."""
    now = time.time() if now is None else now
    started: list[int] = []
    for s in database.due_schedules(now):
        task = ScanTask(
            s["target_url"],
            mode=s["mode"],
            account1=_account_from_profile(s["profile_id"]),
            webhook_url=s["webhook_url"] or None,
        )
        # Потокобезопасная доставка событий в очередь (как в routes/scan.py).
        task.loop = asyncio.get_running_loop()
        # Регистрируем задачу, чтобы _gc_sweep чистил её и отмена работала
        # (как в routes/scan.py: tasks[task.id] = task).
        tasks[task.id] = task
        database.mark_schedule_run(s["id"], now)
        run_scan_in_thread(task)
        started.append(s["id"])
    return started


async def scheduler_loop():
    while True:
        try:
            await asyncio.sleep(SCHEDULER_TICK_SECONDS)
            await run_due_schedules()
        except asyncio.CancelledError:
            break
        except Exception:
            continue
