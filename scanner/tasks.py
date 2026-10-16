"""Задачи сканирования: ScanTask, движок, реестр задач, фоновый GC."""

import asyncio
import threading
import time
import uuid
from contextlib import AsyncExitStack
from typing import Dict, List, Optional

import httpx

import checks
import database

from .config import (
    LOGIN_PATH,
    LOGIN_TOKEN_FIELD,
    QUEUE_MAXSIZE,
    MAX_LOG_LINES,
    LOG_TRIM_CHUNK,
    SESSION_TTL_SECONDS,
    TASK_TTL_SECONDS,
    GC_INTERVAL_SECONDS,
    MODE_TITLES_RU,
    calculate_score,
)
from .security import sessions

# Реестр активных/завершённых задач (очистка — в _gc_loop)
tasks: Dict[str, "ScanTask"] = {}


# ---------- Модели запросов ----------
from pydantic import BaseModel  # noqa: E402


class AccountConfig(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None


class ScanRequest(BaseModel):
    url: str
    mode: str = "full"
    checks: Optional[List[str]] = None
    account1: Optional[AccountConfig] = None
    account2: Optional[AccountConfig] = None


async def login_and_get_token(
    target_url: str, account: Optional[AccountConfig]
) -> Optional[str]:
    if account is None or not account.username or not account.password:
        return None
    url = f"{target_url.rstrip('/')}{LOGIN_PATH}"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as c:
            r = await c.post(url, json={
                "username": account.username,
                "password": account.password,
            })
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    token = data.get(LOGIN_TOKEN_FIELD)
    if not token:
        return None
    return str(token)


# ---------- Задача сканирования ----------
class ScanTask:
    def __init__(
        self,
        target_url: str,
        mode: str = "full",
        selected_checks: Optional[List[str]] = None,
        account1: Optional[AccountConfig] = None,
        account2: Optional[AccountConfig] = None,
    ):
        self.id = str(uuid.uuid4())
        self.target_url = target_url
        self.mode = mode
        self.selected_checks = selected_checks or []
        self.account1 = account1
        self.account2 = account2
        self.status = "pending"
        self.progress = 0.0
        self.logs: List[str] = []
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.score = 100
        self.scan_results: List[dict] = []
        self.error: Optional[str] = None
        self.finished_at: Optional[float] = None
        self.started_at: Optional[float] = None

        self.queue: "asyncio.Queue[dict]" = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def add_log(self, msg: str):
        self.logs.append(msg)
        if len(self.logs) > MAX_LOG_LINES:
            del self.logs[:LOG_TRIM_CHUNK]
        self._push({"type": "log", "message": msg})

    def set_progress(self, value: float):
        self.progress = value
        self._push_status()

    def set_status(self, status: str):
        self.status = status
        if status == "running" and self.started_at is None:
            self.started_at = time.time()
        if status in ("completed", "failed") and self.finished_at is None:
            self.finished_at = time.time()
        self._push_status()
        if status in ("completed", "failed"):
            self._push({"type": "complete", "status": status})

    def update_metrics(self):
        self.critical_count = sum(1 for r in self.scan_results if r["level"] == "CRITICAL")
        self.high_count = sum(1 for r in self.scan_results if r["level"] == "HIGH")
        self.medium_count = sum(1 for r in self.scan_results if r["level"] == "MEDIUM")
        self.low_count = sum(1 for r in self.scan_results if r["level"] == "LOW")
        self.score = calculate_score(
            self.critical_count, self.high_count,
            self.medium_count, self.low_count,
        )
        self._push_status()

    def _push(self, event: dict):
        """Потокобезопасно кладёт событие в очередь."""
        if self.loop is None:
            self._enqueue_event(event)
            return
        try:
            self.loop.call_soon_threadsafe(self._enqueue_event, event)
        except RuntimeError:
            # Event loop уже закрыт — событие просто не доедет, ничего не делаем.
            pass

    def _enqueue_event(self, event: dict):
        """
        Кладёт событие в очередь. Если очередь полна (медленный клиент) —
        выкидываем самое старое событие, чтобы гарантированно
        довезти новое. Это критично для {'type': 'complete'}: без этого
        финальный маркер мог потеряться, и WS-цикл в ws_scan висел бы вечно.
        """
        try:
            self.queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass

        # Очередь полна — освобождаем место, выкинув oldest.
        try:
            self.queue.get_nowait()
        except asyncio.QueueEmpty:
            pass

        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Совсем не повезло — не блокируем сканирование.
            pass

    def _push_status(self):
        self._push({
            "type": "status",
            "status": self.status,
            "progress": self.progress,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "score": self.score,
        })

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "mode": self.mode,
            "selected_checks": self.selected_checks,
            "status": self.status,
            "progress": self.progress,
            "logs": self.logs,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "score": self.score,
            "scan_results": self.scan_results,
            "error": self.error,
        }


async def scan_engine(task: ScanTask):
    task.set_status("running")
    task.add_log(f"=== ЗАПУСК {MODE_TITLES_RU.get(task.mode, 'ПОЛНОГО СКАНИРОВАНИЯ')} ===")

    token1 = None
    token2 = None

    if task.account1 is not None and task.account1.username:
        task.add_log(f"[ИНФО] Аккаунт 1: логин ({task.account1.username})...")
        token1 = await login_and_get_token(task.target_url, task.account1)
        if token1:
            task.add_log("[ИНФО] Аккаунт 1: OK, токен получен")
        else:
            task.add_log("[ОШИБКА] Аккаунт 1: логин не удался")
    else:
        task.add_log("[ИНФО] Аккаунт 1: без авторизации")

    if task.account2 is not None and task.account2.username:
        task.add_log(f"[ИНФО] Аккаунт 2: логин ({task.account2.username})...")
        token2 = await login_and_get_token(task.target_url, task.account2)
        if token2:
            task.add_log("[ИНФО] Аккаунт 2: OK, токен получен")
        else:
            task.add_log("[ОШИБКА] Аккаунт 2: логин не удался")
    else:
        task.add_log("[ИНФО] Аккаунт 2: не используется")

    auth_headers = {"Authorization": f"Bearer {token1}"} if token1 else {}
    auth2_headers = {"Authorization": f"Bearer {token2}"} if token2 else {}

    task.set_progress(0.05)

    check_list = checks.get_checks_by_mode(task.mode, task.selected_checks)
    if not check_list:
        task.add_log("[ОШИБКА] Не выбрано ни одной проверки")
        task.set_status("failed")
        task.error = "No checks selected"
        return

    task.add_log(f"[ИНФО] Всего проверок: {len(check_list)}")

    async with AsyncExitStack() as stack:
        anon_client = await stack.enter_async_context(
            httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        )
        auth_client = await stack.enter_async_context(
            httpx.AsyncClient(timeout=10.0, headers=auth_headers, follow_redirects=False)
        )
        auth2_client: Optional[httpx.AsyncClient] = None
        if auth2_headers:
            auth2_client = await stack.enter_async_context(
                httpx.AsyncClient(timeout=10.0, headers=auth2_headers, follow_redirects=False)
            )

        ctx = checks.ScanContext(
            target_url=task.target_url,
            client=auth_client if auth_headers else anon_client,
            anon_client=anon_client,
            has_auth=bool(auth_headers),
            secondary_client=auth2_client,
            has_auth_secondary=bool(auth2_headers),
        )

        task.add_log("[ИНФО] Получение спецификации OpenAPI...")
        endpoints: List[str] = []
        try:
            res = await ctx.client.get(
                f"{task.target_url}/openapi.json",
                headers={"X-Scan-Start": "1"},
            )
        except httpx.HTTPError as e:
            task.add_log(f"[ОШИБКА] Сетевая ошибка: {e}")
            task.set_status("failed")
            task.error = str(e)
            return

        if res.status_code == 200:
            try:
                data = res.json()
                endpoints = list(data.get("paths", {}).keys())
                task.add_log(f"[OK] Найдено эндпоинтов: {len(endpoints)}")
            except ValueError:
                task.add_log("[ВНИМАНИЕ] Не удалось разобрать openapi.json")
        else:
            task.add_log(f"[ВНИМАНИЕ] Статус openapi.json: {res.status_code}")

        task.set_progress(0.1)
        total = len(check_list)
        for idx, check_func in enumerate(check_list):
            meta = checks.CHECK_METADATA.get(check_func.__name__, {})
            name = meta.get("name", check_func.__name__)
            task.add_log(f"[*] [{idx+1}/{total}] {name}")
            try:
                findings = await check_func(ctx, endpoints)
            except Exception as e:
                task.add_log(f"[ОШИБКА] Проверка {name} упала: {e}")
                findings = []
            if findings:
                task.scan_results.extend(findings)
                task.add_log(f"[!] Найдено уязвимостей: {len(findings)}")
                for f in findings:
                    task.add_log(f"    {f['level']}: {f['desc']}")
            else:
                task.add_log("[OK] Уязвимостей не обнаружено")
            task.update_metrics()
            task.set_progress(0.1 + (idx + 1) / total * 0.85)

        task.set_progress(1.0)
        task.add_log(f"=== СКАНИРОВАНИЕ ЗАВЕРШЕНО (Score: {task.score}) ===")

        # Сначала сохраняем в историю, потом отправляем "complete" —
        # иначе UI показывает «ГОТОВО», а записи в БД нет.
        try:
            database.save_scan(
                target_url=task.target_url,
                critical=task.critical_count,
                high=task.high_count,
                medium=task.medium_count,
                low=task.low_count,
                results=task.scan_results,
            )
            task.add_log("[OK] Результаты сохранены в историю")
        except Exception as e:
            task.add_log(f"[ОШИБКА] Не удалось сохранить: {e}")

        task.set_status("completed")


def run_scan_in_thread(task: ScanTask):
    def target():
        try:
            asyncio.run(scan_engine(task))
        except BaseException as e:
            try:
                task.error = str(e)
                task.add_log(f"[ОШИБКА] Критический сбой сканирования: {e}")
                task.set_status("failed")
            except Exception:
                pass
    threading.Thread(target=target, daemon=True).start()


# ---------- Фоновая очистка ----------
async def gc_loop():
    while True:
        try:
            await asyncio.sleep(GC_INTERVAL_SECONDS)
            now = time.time()

            for sid in list(sessions.keys()):
                entry = sessions.get(sid)
                if not entry:
                    continue
                _, created_at = entry
                if now - created_at > SESSION_TTL_SECONDS:
                    sessions.pop(sid, None)

            for tid in list(tasks.keys()):
                task = tasks.get(tid)
                if not task:
                    continue
                if task.finished_at and now - task.finished_at > TASK_TTL_SECONDS:
                    tasks.pop(tid, None)
        except asyncio.CancelledError:
            break
        except Exception:
            continue
