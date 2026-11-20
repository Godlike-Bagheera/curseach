"""Задачи сканирования: ScanTask, движок, реестр задач, фоновый GC."""

import asyncio
import os
import sqlite3
import threading
import time
import uuid
from contextlib import AsyncExitStack

import httpx

import checks
import database

from .config import (
    GC_INTERVAL_SECONDS,
    LOG_TRIM_CHUNK,
    LOGIN_PATH,
    LOGIN_TOKEN_FIELD,
    MAX_CONCURRENT_SCANS,
    MAX_LOG_LINES,
    MODE_TITLES_RU,
    QUEUE_MAXSIZE,
    SCAN_CONCURRENCY,
    SCAN_MAX_REQUESTS,
    SCAN_RPS,
    SCAN_TOTAL_TIMEOUT,
    SESSION_TTL_SECONDS,
    TASK_TTL_SECONDS,
    calculate_score,
)
from .security import pinned_client_kwargs, sessions

# Реестр активных/завершённых задач (очистка — в _gc_loop)
tasks: dict[str, "ScanTask"] = {}


# ---------- Модели запросов ----------
from pydantic import BaseModel  # noqa: E402


class AccountConfig(BaseModel):
    username: str | None = None
    password: str | None = None


class ScanRequest(BaseModel):
    url: str
    mode: str = "full"
    checks: list[str] | None = None
    account1: AccountConfig | None = None
    account2: AccountConfig | None = None
    seed: int | None = None  # детерминированный профиль учебной цели (X-Scan-Seed)


async def login_and_get_token(target_url: str, account: AccountConfig | None) -> str | None:
    if account is None or not account.username or not account.password:
        return None
    url = f"{target_url.rstrip('/')}{LOGIN_PATH}"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, **pinned_client_kwargs(target_url)) as c:
            r = await c.post(
                url,
                json={
                    "username": account.username,
                    "password": account.password,
                },
            )
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
        selected_checks: list[str] | None = None,
        account1: AccountConfig | None = None,
        account2: AccountConfig | None = None,
        seed: int | None = None,
    ):
        self.id = str(uuid.uuid4())
        self.seed = seed
        self.cancel_event = threading.Event()
        self.target_url = target_url
        self.mode = mode
        self.selected_checks = selected_checks or []
        self.account1 = account1
        self.account2 = account2
        self.status = "pending"
        self.partial = False
        self.partial_reason = ""
        self.progress = 0.0
        self.logs: list[str] = []
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.score = 100
        self.scan_results: list[dict] = []
        self.error: str | None = None
        self.finished_at: float | None = None
        self.started_at: float | None = None
        self.budget: checks.RequestBudget | None = None

        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self.loop: asyncio.AbstractEventLoop | None = None

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
        if status in ("completed", "failed", "cancelled") and self.finished_at is None:
            self.finished_at = time.time()
        self._push_status()
        if status in ("completed", "failed", "cancelled"):
            self._push({"type": "complete", "status": status})

    def update_metrics(self):
        self.critical_count = sum(1 for r in self.scan_results if r["level"] == "CRITICAL")
        self.high_count = sum(1 for r in self.scan_results if r["level"] == "HIGH")
        self.medium_count = sum(1 for r in self.scan_results if r["level"] == "MEDIUM")
        self.low_count = sum(1 for r in self.scan_results if r["level"] == "LOW")
        self.score = calculate_score(
            self.critical_count,
            self.high_count,
            self.medium_count,
            self.low_count,
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
        self._push(
            {
                "type": "status",
                "status": self.status,
                "progress": self.progress,
                "critical_count": self.critical_count,
                "high_count": self.high_count,
                "medium_count": self.medium_count,
                "low_count": self.low_count,
                "score": self.score,
                "requests_used": self.budget.used if self.budget else 0,
                "requests_max": self.budget.max_requests if self.budget else SCAN_MAX_REQUESTS,
            }
        )

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "mode": self.mode,
            "selected_checks": self.selected_checks,
            "status": self.status,
            "partial": self.partial,
            "partial_reason": self.partial_reason,
            "progress": self.progress,
            "logs": self.logs,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "score": self.score,
            "requests_used": self.budget.used if self.budget else 0,
            "requests_max": self.budget.max_requests if self.budget else SCAN_MAX_REQUESTS,
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
        pin_kw = pinned_client_kwargs(task.target_url)
        anon_client = await stack.enter_async_context(httpx.AsyncClient(timeout=10.0, follow_redirects=False, **pin_kw))
        auth_client = await stack.enter_async_context(
            httpx.AsyncClient(timeout=10.0, headers=auth_headers, follow_redirects=False, **pin_kw)
        )
        auth2_client: httpx.AsyncClient | None = None
        if auth2_headers:
            auth2_client = await stack.enter_async_context(
                httpx.AsyncClient(timeout=10.0, headers=auth2_headers, follow_redirects=False, **pin_kw)
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
        endpoints: list[str] = []
        try:
            spec_headers = {"X-Scan-Start": "1"}
            if task.seed is not None:
                spec_headers["X-Scan-Seed"] = str(task.seed)
            res = await ctx.client.get(
                f"{task.target_url}/openapi.json",
                headers=spec_headers,
            )
        except httpx.HTTPError as e:
            task.add_log(f"[ОШИБКА] Сетевая ошибка: {e}")
            task.set_status("failed")
            task.error = str(e)
            return

        if res.status_code == 200:
            try:
                data = res.json()
                if isinstance(data, dict):
                    ctx.openapi = data
                    paths = data.get("paths")
                    endpoints = list(paths.keys()) if isinstance(paths, dict) else []
                task.add_log(f"[OK] Найдено эндпоинтов: {len(endpoints)}")
            except ValueError:
                task.add_log("[ВНИМАНИЕ] Не удалось разобрать openapi.json")
        else:
            task.add_log(f"[ВНИМАНИЕ] Статус openapi.json: {res.status_code}")

        if not endpoints:
            from checks.discovery import discover_endpoints

            task.add_log("[ИНФО] Спеки нет — discovery (robots.txt / sitemap.xml / common-paths)...")
            endpoints = await discover_endpoints(ctx)
            task.add_log(f"[OK] Discovery нашёл путей: {len(endpoints)}")

        task.set_progress(0.1)
        total = len(check_list)

        # Инфраструктура: параллелизм, бюджет, RPS, отмена.
        ctx.semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)
        per_check_cap = max(60, SCAN_MAX_REQUESTS // len(check_list) * 4)
        ctx.budget = checks.RequestBudget(SCAN_MAX_REQUESTS, per_check_cap=per_check_cap)
        task.budget = ctx.budget
        ctx.limiter = checks.RateLimiter(SCAN_RPS) if SCAN_RPS > 0 else None
        ctx.cancel_event = task.cancel_event
        ctx.scan_seed = task.seed
        task.add_log(
            f"[ИНФО] Параллелизм: {SCAN_CONCURRENCY} запросов, бюджет {SCAN_MAX_REQUESTS} "
            f"(квота на проверку: {per_check_cap}), RPS {SCAN_RPS:g}, таймаут {SCAN_TOTAL_TIMEOUT}s"
        )

        done = 0

        async def run_one(check_func):
            nonlocal done
            meta = checks.CHECK_METADATA.get(check_func.__name__, {})
            name = meta.get("name", check_func.__name__)
            task.add_log(f"[*] {name} — старт")
            evidence_log: list[dict] = []
            tok_ctx = checks._SCAN_CTX.set(ctx)
            tok_log = checks._EVIDENCE_LOG.set(evidence_log)
            tok_name = checks._CHECK_NAME.set(check_func.__name__)
            try:
                findings = await check_func(ctx, endpoints)
            except checks.ScanCancelled:
                raise
            except Exception as e:
                task.add_log(f"[ОШИБКА] Проверка {name} упала: {e}")
                findings = []
            finally:
                checks._SCAN_CTX.reset(tok_ctx)
                checks._EVIDENCE_LOG.reset(tok_log)
                checks._CHECK_NAME.reset(tok_name)
            findings = checks.enrich_findings(findings or [], evidence_log)
            if findings:
                task.scan_results.extend(findings)
                task.add_log(f"[!] {name}: найдено {len(findings)}")
                for f in findings:
                    task.add_log(f"    {f['level']}: {f['desc']}")
            else:
                task.add_log(f"[OK] {name}: уязвимостей не обнаружено")
            done += 1
            task.update_metrics()
            task.set_progress(0.1 + done / total * 0.85)
            return findings

        cancelled = False
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*(run_one(fn) for fn in check_list), return_exceptions=True),
                timeout=SCAN_TOTAL_TIMEOUT,
            )
            for r in results:
                if isinstance(r, checks.ScanCancelled):
                    cancelled = True
        except asyncio.TimeoutError:
            task.partial = True
            task.partial_reason = f"общий таймаут {SCAN_TOTAL_TIMEOUT}s"
            task.add_log(f"[ВНИМАНИЕ] Общий таймаут скана ({SCAN_TOTAL_TIMEOUT}s) — сохраняем частичные результаты")
        except asyncio.CancelledError:
            cancelled = True
            task.partial = True
            task.partial_reason = "скан отменён"
            task.partial = True
            task.partial_reason = "скан отменён"

        if ctx.budget is not None and ctx.budget.per_check_capped:
            capped = ", ".join(sorted(ctx.budget.per_check_capped))
            task.add_log(f"[ВНИМАНИЕ] Квота запросов исчерпана для проверок: {capped} — часть их запросов пропущена")

        if ctx.budget is not None and ctx.budget.exhausted:
            task.partial = True
            task.partial_reason = f"бюджет запросов исчерпан ({SCAN_MAX_REQUESTS})"
            task.add_log(f"[ВНИМАНИЕ] Бюджет запросов исчерпан ({SCAN_MAX_REQUESTS}) — часть запросов пропущена")

        before = len(task.scan_results)
        task.scan_results = checks.dedup_findings(task.scan_results)
        if before != len(task.scan_results):
            task.add_log(f"[ИНФО] Дедупликация: {before} → {len(task.scan_results)} находок")
        task.update_metrics()

        if cancelled:
            task.add_log("=== СКАН ОТМЕНЁН ПОЛЬЗОВАТЕЛЕМ ===")
            task.set_status("cancelled")
            return

        task.set_progress(1.0)
        task.add_log(f"=== СКАНИРОВАНИЕ ЗАВЕРШЕНО (Score: {task.score}) ===")

        # Сначала сохраняем в историю, потом отправляем "complete" —
        # иначе UI показывает «ГОТОВО», а записи в БД нет.
        try:
            # Самовосстановление: если процесс сканера был запущен со старым
            # кодом (до init_db на startup) или файл БД удалён — создаём схему
            # и повторяем сохранение. Исключение из этого места больше не должно
            # приводить к "no such table: scans".
            try:
                database.save_scan(
                    target_url=task.target_url,
                    critical=task.critical_count,
                    high=task.high_count,
                    medium=task.medium_count,
                    low=task.low_count,
                    results=task.scan_results,
                    mode=task.mode,
                    partial=task.partial,
                    partial_reason=task.partial_reason,
                )
            except sqlite3.OperationalError:
                database.init_db()  # пересоздаём схему и пробуем ещё раз
                database.save_scan(
                    target_url=task.target_url,
                    critical=task.critical_count,
                    high=task.high_count,
                    medium=task.medium_count,
                    low=task.low_count,
                    results=task.scan_results,
                    mode=task.mode,
                    partial=task.partial,
                    partial_reason=task.partial_reason,
                )
            task.add_log("[OK] Результаты сохранены в историю")
        except Exception as e:
            task.add_log(f"[ОШИБКА] Не удалось сохранить: {e}")

        task.set_status("completed")


# Лимит одновременных сканов на процесс (thread-per-scan без потолка был DoS-риском).
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def run_scan_in_thread(task: ScanTask):
    if not _scan_slots.acquire(blocking=False):
        task.error = f"Достигнут лимит одновременных сканов ({MAX_CONCURRENT_SCANS}) — попробуйте позже"
        task.add_log(f"[ОШИБКА] {task.error}")
        task.set_status("failed")
        return

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
        finally:
            _scan_slots.release()

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

            retention = int(os.environ.get("SCANNER_HISTORY_RETENTION_DAYS", "0") or 0)
            if retention > 0:
                import database

                database.prune_old_scans(retention)
        except asyncio.CancelledError:
            break
        except Exception:
            continue
