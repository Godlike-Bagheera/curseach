"""
DevSecOps Scanner — веб-сервер.
- Аутентификация через серверные сессии + HttpOnly cookie
- WebSockets для трансляции логов и статуса
- Jinja2 для HTML-отчётов (about.html раздаётся как FileResponse, не через Jinja)
- Security Score: 100 - (CRIT×20 + HIGH×10 + MED×5 + LOW×2)
- Фоновая очистка сессий и завершённых задач (защита от утечки RAM)
- Два аккаунта для авторизованных сканов и cross-user IDOR / BFLA
- Экспорт отчётов: HTML, JSON, CSV, XLSX, PDF, ZIP (серверный рендер через Playwright)
"""

import asyncio
import datetime
import hashlib
import io
import json as _json
import os
import re
import secrets
import threading
import time
import uuid
import zipfile
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import (
    Cookie, Depends, FastAPI, Form, HTTPException, Request,
    WebSocket, WebSocketDisconnect,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import checks
import database
import report_csv
import report_xlsx


# ---------- Настройки автологина ----------
LOGIN_PATH = "/api/auth/login"
LOGIN_TOKEN_FIELD = "token"


# ---------- Учётные данные сканера ----------
_SALT = b"devsecops_static_salt_v1"
_KDF_ITERATIONS = 100_000

ADMIN_USER = "admin"
GUEST_USER = "guest"


def _hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _SALT, _KDF_ITERATIONS
    ).hex()


ADMIN_PASSWORD_HASH = _hash_password("admin")
GUEST_PASSWORD_HASH = _hash_password("guest")


def authenticate(username: str, password: str) -> Optional[str]:
    provided = _hash_password(password)
    if secrets.compare_digest(username.encode(), ADMIN_USER.encode()) and \
       secrets.compare_digest(provided, ADMIN_PASSWORD_HASH):
        return "admin"
    if secrets.compare_digest(username.encode(), GUEST_USER.encode()) and \
       secrets.compare_digest(provided, GUEST_PASSWORD_HASH):
        return "guest"
    return None


# ---------- Сессии ----------
sessions: Dict[str, Tuple[str, float]] = {}

SESSION_TTL_SECONDS = 8 * 60 * 60
TASK_TTL_SECONDS = 60 * 60
GC_INTERVAL_SECONDS = 5 * 60

QUEUE_MAXSIZE = 1000
MAX_LOG_LINES = 5000
LOG_TRIM_CHUNK = 1000


def create_session(username: str) -> str:
    sid = secrets.token_urlsafe(32)
    sessions[sid] = (username, time.time())
    return sid


def destroy_session(sid: Optional[str]) -> None:
    if sid and sid in sessions:
        sessions.pop(sid, None)


def get_current_user(session_id: Optional[str] = Cookie(None)) -> Optional[str]:
    if not session_id:
        return None
    entry = sessions.get(session_id)
    if not entry:
        return None
    username, created_at = entry
    if time.time() - created_at > SESSION_TTL_SECONDS:
        sessions.pop(session_id, None)
        return None
    sessions[session_id] = (username, time.time())
    return username


def require_user(session_id: Optional[str] = Cookie(None)) -> str:
    user = get_current_user(session_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(session_id: Optional[str] = Cookie(None)) -> str:
    user = require_user(session_id)
    if user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def calculate_score(critical: int, high: int, medium: int, low: int) -> int:
    penalty = critical * 20 + high * 10 + medium * 5 + low * 2
    return max(0, 100 - penalty)


# ---------- Проверка Origin ----------
def _origin_allowed(origin: str) -> bool:
    if not origin:
        return True
    try:
        p = urlparse(origin)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1")


# ---------- Фоновая очистка ----------
async def _gc_loop():
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    gc_task = asyncio.create_task(_gc_loop())
    try:
        yield
    finally:
        gc_task.cancel()
        try:
            await gc_task
        except (asyncio.CancelledError, Exception):
            pass


# ---------- Приложение ----------
app = FastAPI(title="DevSecOps Scanner", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

database.init_db()

tasks: Dict[str, "ScanTask"] = {}


MODE_TITLES_RU = {
    "quick": "БЫСТРОЕ СКАНИРОВАНИЕ",
    "full": "ПОЛНОЕ СКАНИРОВАНИЕ",
    "custom": "ВЫБОРОЧНОЕ СКАНИРОВАНИЕ",
}

MODE_TITLES_REPORT = {
    "quick": "БЫСТРАЯ ПРОВЕРКА",
    "full": "ПОЛНАЯ ПРОВЕРКА",
    "custom": "ВЫБОРОЧНАЯ ПРОВЕРКА",
}

_LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ---------- CSRF через Origin / Referer ----------
@app.middleware("http")
async def enforce_origin_on_mutations(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin:
            if not _origin_allowed(origin):
                return JSONResponse(
                    {"detail": "Forbidden origin"}, status_code=403
                )
        else:
            referer = request.headers.get("referer")
            if referer and not _origin_allowed(referer):
                return JSONResponse(
                    {"detail": "Forbidden referer"}, status_code=403
                )
    return await call_next(request)


# ---------- Модели ----------
class AccountConfig(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None


class ScanRequest(BaseModel):
    url: str
    mode: str = "full"
    checks: Optional[List[str]] = None
    account1: Optional[AccountConfig] = None
    account2: Optional[AccountConfig] = None


def _validate_target_url(url: str) -> Optional[str]:
    """
    Проверяет URL. Использует urlparse вместо ручного split — так
    корректно обрабатываются IPv6-адреса вида http://[::1]:8000,
    user:pass@host и прочие нестандартные формы.
    """
    if not url:
        return "URL не задан"
    if not isinstance(url, str):
        return "URL должен быть строкой"

    url = url.strip()
    if not url:
        return "URL не задан"

    if not (url.startswith("http://") or url.startswith("https://")):
        return "URL должен начинаться с http:// или https://"

    if any(c in url for c in (" ", "\t", "\n", "\r", '"', "'", "<", ">")):
        return "URL содержит недопустимые символы"

    try:
        parsed = urlparse(url)
    except Exception:
        return "Не удалось разобрать URL"

    host = parsed.hostname
    if not host:
        return "URL не содержит хост"

    host_lower = host.lower()

    # urlparse возвращает hostname для IPv6 БЕЗ квадратных скобок,
    # например '::1' — поэтому ':' в hostname = это IPv6.
    if ":" in host_lower:
        return None

    allowed_plain = ("localhost", "127.0.0.1")
    if "." not in host_lower and host_lower not in allowed_plain:
        return f"Некорректный хост: {host}"

    return None


def _safe_host_for_filename(target_url: str) -> str:
    try:
        parsed = urlparse(target_url)
        host = parsed.netloc or parsed.hostname or "target"
    except Exception:
        host = "target"
    host = re.sub(r"[^A-Za-z0-9._\-]", "-", host)
    host = host.strip("-") or "target"
    return host


async def _login_and_get_token(
    target_url: str, account: Optional[AccountConfig]
) -> Optional[str]:
    if account is None or not account.username or not account.password:
        return None
    url = f"{target_url.rstrip('/')}{LOGIN_PATH}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
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
        token1 = await _login_and_get_token(task.target_url, task.account1)
        if token1:
            task.add_log("[ИНФО] Аккаунт 1: OK, токен получен")
        else:
            task.add_log("[ОШИБКА] Аккаунт 1: логин не удался")
    else:
        task.add_log("[ИНФО] Аккаунт 1: без авторизации")

    if task.account2 is not None and task.account2.username:
        task.add_log(f"[ИНФО] Аккаунт 2: логин ({task.account2.username})...")
        token2 = await _login_and_get_token(task.target_url, task.account2)
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
            httpx.AsyncClient(timeout=10.0)
        )
        auth_client = await stack.enter_async_context(
            httpx.AsyncClient(timeout=10.0, headers=auth_headers)
        )
        auth2_client: Optional[httpx.AsyncClient] = None
        if auth2_headers:
            auth2_client = await stack.enter_async_context(
                httpx.AsyncClient(timeout=10.0, headers=auth2_headers)
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


# ---------- Логин / Выход ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session_id: Optional[str] = Cookie(None)):
    if get_current_user(session_id):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate(username, password)
    if user is None:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Неверный логин или пароль"},
            status_code=401,
        )
    sid = create_session(user)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="session_id",
        value=sid,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    return resp


@app.get("/logout")
async def logout(session_id: Optional[str] = Cookie(None)):
    destroy_session(session_id)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session_id", path="/")
    return resp


# ---------- Главная ----------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_current_user(session_id)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "index.html", {
        "user": user,
        "is_guest": user == "guest",
    })


# ---------- Защищённые маршруты ----------
@app.get("/available-checks")
async def available_checks(user: str = Depends(require_admin)):
    return JSONResponse(checks.get_available_checks())


@app.post("/scan")
async def start_scan(req: ScanRequest, user: str = Depends(require_admin)):
    if req.mode not in ("quick", "full", "custom"):
        raise HTTPException(status_code=400, detail="Invalid mode")
    if req.mode == "custom" and not req.checks:
        raise HTTPException(status_code=400, detail="No checks selected")

    url_err = _validate_target_url(req.url)
    if url_err:
        raise HTTPException(status_code=400, detail=url_err)

    task = ScanTask(
        req.url.strip(),
        mode=req.mode,
        selected_checks=req.checks,
        account1=req.account1,
        account2=req.account2,
    )
    task.loop = asyncio.get_running_loop()
    tasks[task.id] = task
    run_scan_in_thread(task)
    return {"task_id": task.id, "mode": task.mode}


@app.get("/status/{task_id}")
async def get_status(task_id: str, user: str = Depends(require_admin)):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.to_dict()


@app.websocket("/ws/scan/{task_id}")
async def ws_scan(websocket: WebSocket, task_id: str):
    await websocket.accept()

    origin = websocket.headers.get("origin", "")
    if origin and not _origin_allowed(origin):
        await websocket.send_json({"type": "error", "message": "Не авторизовано"})
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
        return

    sid = websocket.cookies.get("session_id")
    user = None
    if sid:
        entry = sessions.get(sid)
        if entry:
            username, created_at = entry
            if time.time() - created_at <= SESSION_TTL_SECONDS:
                user = username
    if user != "admin":
        await websocket.send_json({"type": "error", "message": "Не авторизовано"})
        try:
            await websocket.close()
        except Exception:
            pass
        return

    task = tasks.get(task_id)
    if task is None:
        await websocket.send_json({"type": "error", "message": "Задача не найдена"})
        try:
            await websocket.close()
        except Exception:
            pass
        return

    await websocket.send_json({
        "type": "init",
        "logs": list(task.logs),
        "status": task.status,
        "progress": task.progress,
        "critical_count": task.critical_count,
        "high_count": task.high_count,
        "medium_count": task.medium_count,
        "low_count": task.low_count,
        "score": task.score,
    })

    if task.status in ("completed", "failed"):
        await websocket.send_json({"type": "complete", "status": task.status})
        try:
            await websocket.close()
        except Exception:
            pass
        return

    try:
        while True:
            event = await task.queue.get()
            await websocket.send_json(event)
            if event.get("type") == "complete":
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/report/html/{task_id}", response_class=HTMLResponse)
async def get_html_report(task_id: str, request: Request, user: str = Depends(require_admin)):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan not finished")

    scan_dt = datetime.datetime.fromtimestamp(task.finished_at or time.time())

    return render_report(
        request=request,
        target_url=task.target_url,
        results=task.scan_results,
        critical=task.critical_count,
        high=task.high_count,
        medium=task.medium_count,
        low=task.low_count,
        score=task.score,
        mode=task.mode,
        scan_date=scan_dt.strftime("%Y-%m-%d %H:%M:%S"),
    )


# =============================================================
#   ИСТОРИЯ: страницы, PDF, ZIP, экспорт
# =============================================================

def _build_chart_context(scan: dict, include_findings: bool = False) -> dict:
    """
    Готовит контекст шаблонов chart.html / report_full.html
    из записи истории.
    """
    results = scan.get("results") or []

    by_type: Dict[str, int] = {}
    by_type_level: Dict[str, str] = {}
    for f in results:
        t = f.get("type", "Unknown")
        lvl = f.get("level", "LOW")
        by_type[t] = by_type.get(t, 0) + 1
        if t not in by_type_level or \
           _LEVEL_RANK.get(lvl, 99) < _LEVEL_RANK.get(by_type_level[t], 99):
            by_type_level[t] = lvl

    total = scan["critical"] + scan["high"] + scan["medium"] + scan["low"]
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])

    types_sorted = sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))
    types_data = [
        {
            "type": t,
            "level": by_type_level[t],
            "count": c,
            "percent": round(c * 100 / total, 1) if total else 0.0,
        }
        for t, c in types_sorted
    ]

    ctx = {
        "scan_id": scan["id"],
        "target_url": scan["target_url"],
        "scan_date": scan["scan_date"].replace("T", " ")[:19],
        "critical": scan["critical"],
        "high": scan["high"],
        "medium": scan["medium"],
        "low": scan["low"],
        "total": total,
        "score": score,
        "types_data": types_data,
    }

    if include_findings:
        ctx["findings"] = results
        ctx["mode_ru"] = "ПОЛНАЯ ПРОВЕРКА"

    return ctx


def _inline_chartjs(html: str) -> str:
    """
    Заменяет <script src="/static/chart.umd.min.js"></script> на
    inline-версию Chart.js. Нужно для ZIP-архива: распакованный HTML
    не имеет доступа к /static/, и без этого диаграмма не отрисуется.
    Если файл Chart.js недоступен — возвращает HTML без изменений.
    """
    try:
        chart_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "static", "chart.umd.min.js",
        )
        with open(chart_path, "r", encoding="utf-8") as f:
            chart_js = f.read()
    except Exception:
        return html

    return html.replace(
        '<script src="/static/chart.umd.min.js"></script>',
        f"<script>{chart_js}</script>",
    )


@app.get("/history/{scan_id}/view", response_class=HTMLResponse)
async def view_history_report(scan_id: int, request: Request, user: str = Depends(require_admin)):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    return templates.TemplateResponse(request, "report.html", {
        "target_url": scan["target_url"],
        "findings": scan["results"],
        "critical": scan["critical"],
        "high": scan["high"],
        "medium": scan["medium"],
        "low": scan["low"],
        "score": score,
        "mode_ru": "ПОЛНАЯ ПРОВЕРКА",
        "scan_date": scan["scan_date"].replace("T", " ")[:19],
        "source": "history",
        "scan_id": scan["id"],
    })


@app.get("/history/{scan_id}/chart", response_class=HTMLResponse)
async def view_history_chart(scan_id: int, request: Request, user: str = Depends(require_admin)):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    ctx = _build_chart_context(scan)
    return templates.TemplateResponse(request, "chart.html", ctx)


@app.get("/history/{scan_id}/full", response_class=HTMLResponse)
async def view_history_full(scan_id: int, request: Request, user: str = Depends(require_admin)):
    """Страница с объединённым отчётом: диаграмма + таблица находок."""
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    ctx = _build_chart_context(scan, include_findings=True)
    return templates.TemplateResponse(request, "report_full.html", ctx)


# ---------- PDF через Playwright ----------
async def _render_pdf_bytes(
    page_url: str,
    base_url: str,
    wait_ms: int = 600,
) -> bytes:
    """
    Открывает указанную страницу в headless Chromium,
    ждёт отрисовки и возвращает PDF-байты.

    Для внутреннего рендера создаёт собственную admin-сессию —
    это позволяет вызывать PDF-экспорт (в т.ч. из /bundle) без cookie
    пользователя: например, из скриптов или CI.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=(
                "Playwright не установлен. Выполните: "
                "pip install playwright && python -m playwright install chromium"
            ),
        )

    internal_sid = create_session("admin")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            try:
                context = await browser.new_context()
                await context.add_cookies([{
                    "name": "session_id",
                    "value": internal_sid,
                    "url": base_url,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }])
                page = await context.new_page()
                await page.goto(page_url, wait_until="networkidle")
                await page.wait_for_timeout(wait_ms)
                pdf_bytes = await page.pdf(
                    format="A4",
                    print_background=True,
                    prefer_css_page_size=True,
                )
                return pdf_bytes
            finally:
                await browser.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Не удалось сгенерировать PDF: {e}",
        )
    finally:
        destroy_session(internal_sid)


@app.get("/history/{scan_id}/chart/pdf")
async def download_history_chart_pdf(
    scan_id: int,
    request: Request,
    user: str = Depends(require_admin),
):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    base = f"{request.url.scheme}://{request.url.netloc}"
    pdf_bytes = await _render_pdf_bytes(
        page_url=f"{base}/history/{scan_id}/chart",
        base_url=base,
    )
    filename = f"scan_{scan_id}_chart.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/history/{scan_id}/view/pdf")
async def download_history_view_pdf(
    scan_id: int,
    request: Request,
    user: str = Depends(require_admin),
):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    base = f"{request.url.scheme}://{request.url.netloc}"
    pdf_bytes = await _render_pdf_bytes(
        page_url=f"{base}/history/{scan_id}/view",
        base_url=base,
    )
    filename = f"scan_{scan_id}_report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/history/{scan_id}/full/pdf")
async def download_history_full_pdf(
    scan_id: int,
    request: Request,
    user: str = Depends(require_admin),
):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    base = f"{request.url.scheme}://{request.url.netloc}"
    pdf_bytes = await _render_pdf_bytes(
        page_url=f"{base}/history/{scan_id}/full",
        base_url=base,
        wait_ms=800,
    )
    filename = f"scan_{scan_id}_full.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------- ZIP-архив со всеми форматами ----------
@app.get("/history/{scan_id}/bundle")
async def download_history_bundle(
    scan_id: int,
    request: Request,
    user: str = Depends(require_admin),
):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 1. HTML (полный — диаграмма + таблица).
    #    Chart.js инлайним в HTML, чтобы распакованный файл
    #    не зависел от /static/ и диаграмма рисовалась офлайн.
    html_ctx = _build_chart_context(scan, include_findings=True)
    html_str = templates.get_template("report_full.html").render(html_ctx)
    html_str = _inline_chartjs(html_str)
    html_bytes = html_str.encode("utf-8")

    # 2. JSON
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    json_payload = {
        "scan_date": scan["scan_date"],
        "target": scan["target_url"],
        "mode": "full",
        "metrics": {
            "score": score,
            "critical": scan["critical"],
            "high": scan["high"],
            "medium": scan["medium"],
            "low": scan["low"],
        },
        "findings": scan.get("results") or [],
    }
    json_bytes = _json.dumps(
        json_payload, ensure_ascii=False, indent=2
    ).encode("utf-8")

    # 3. CSV
    scan_dt = datetime.datetime.fromisoformat(scan["scan_date"])
    csv_bytes = report_csv.generate_csv(
        target_url=scan["target_url"],
        mode="full",
        scan_dt=scan_dt,
        score=score,
        critical=scan["critical"],
        high=scan["high"],
        medium=scan["medium"],
        low=scan["low"],
        findings=scan.get("results") or [],
    )

    # 4. XLSX
    xlsx_bytes: Optional[bytes] = None
    if report_xlsx.is_available():
        xlsx_bytes = report_xlsx.generate_xlsx(
            target_url=scan["target_url"],
            mode="full",
            scan_dt=scan_dt,
            score=score,
            critical=scan["critical"],
            high=scan["high"],
            medium=scan["medium"],
            low=scan["low"],
            findings=scan.get("results") or [],
        )

    # 5. PDF (объединённый) — внутренняя admin-сессия создаётся в _render_pdf_bytes.
    base = f"{request.url.scheme}://{request.url.netloc}"
    pdf_bytes = await _render_pdf_bytes(
        page_url=f"{base}/history/{scan_id}/full",
        base_url=base,
        wait_ms=800,
    )

    # Собираем ZIP
    host_part = _safe_host_for_filename(scan["target_url"])
    date_part = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    zip_name = f"scan_{scan_id}_{host_part}_{date_part}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"scan_{scan_id}/report.html", html_bytes)
        zf.writestr(f"scan_{scan_id}/report.json", json_bytes)
        zf.writestr(f"scan_{scan_id}/report.csv", csv_bytes)
        if xlsx_bytes is not None:
            zf.writestr(f"scan_{scan_id}/report.xlsx", xlsx_bytes)
        zf.writestr(f"scan_{scan_id}/report.pdf", pdf_bytes)

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
    )


# ---------- Экспорт всей истории ----------
@app.get("/history/export.xlsx")
async def export_history_xlsx(user: str = Depends(require_admin)):
    """Сводный XLSX по всем сканам в истории."""
    if not report_xlsx.is_available():
        raise HTTPException(
            status_code=503,
            detail="openpyxl не установлен. Выполните: pip install openpyxl",
        )

    scans = database.get_all_scans()
    content = report_xlsx.generate_history_xlsx(scans)
    if content is None:
        raise HTTPException(
            status_code=500,
            detail="Не удалось сформировать XLSX-отчёт",
        )

    date_part = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"history_{date_part}.xlsx"

    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# =============================================================
#   ОСТАЛЬНЫЕ РОУТЫ (JSON/CSV/XLSX по активной задаче)
# =============================================================

def render_report(request, target_url, results, critical, high, medium, low, score, mode, scan_date):
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "target_url": target_url,
            "findings": results,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "score": score,
            "mode_ru": MODE_TITLES_REPORT.get(mode, "ПОЛНАЯ ПРОВЕРКА"),
            "scan_date": scan_date,
            "source": "task",
            "scan_id": None,
        },
    )


@app.get("/report/json/{task_id}")
async def get_json_report(task_id: str, user: str = Depends(require_admin)):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan not finished")
    return JSONResponse({
        "scan_date": datetime.datetime.now().isoformat(),
        "target": task.target_url,
        "mode": task.mode,
        "selected_checks": task.selected_checks,
        "metrics": {
            "score": task.score,
            "critical": task.critical_count,
            "high": task.high_count,
            "medium": task.medium_count,
            "low": task.low_count,
        },
        "findings": task.scan_results,
    })


@app.get("/report/csv/{task_id}")
async def get_csv_report(task_id: str, user: str = Depends(require_admin)):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan not finished")

    scan_dt = datetime.datetime.fromtimestamp(task.finished_at or time.time())
    content = report_csv.generate_csv(
        target_url=task.target_url,
        mode=task.mode,
        scan_dt=scan_dt,
        score=task.score,
        critical=task.critical_count,
        high=task.high_count,
        medium=task.medium_count,
        low=task.low_count,
        findings=task.scan_results,
    )

    host_part = _safe_host_for_filename(task.target_url)
    date_part = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"scan_{host_part}_{date_part}.csv"

    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/report/xlsx/{task_id}")
async def get_xlsx_report(task_id: str, user: str = Depends(require_admin)):
    if not report_xlsx.is_available():
        raise HTTPException(
            status_code=503,
            detail="openpyxl не установлен. Выполните: pip install openpyxl",
        )

    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan not finished")

    scan_dt = datetime.datetime.fromtimestamp(task.finished_at or time.time())
    content = report_xlsx.generate_xlsx(
        target_url=task.target_url,
        mode=task.mode,
        scan_dt=scan_dt,
        score=task.score,
        critical=task.critical_count,
        high=task.high_count,
        medium=task.medium_count,
        low=task.low_count,
        findings=task.scan_results,
    )

    if content is None:
        raise HTTPException(
            status_code=500,
            detail="Не удалось сформировать XLSX-отчёт",
        )

    host_part = _safe_host_for_filename(task.target_url)
    date_part = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"scan_{host_part}_{date_part}.xlsx"

    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/history")
async def get_history(user: str = Depends(require_admin)):
    return JSONResponse(database.get_all_scans())


@app.get("/history/{scan_id}")
async def get_history_item(scan_id: int, user: str = Depends(require_admin)):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(scan)


@app.delete("/history/{scan_id}")
async def delete_history_item(scan_id: int, user: str = Depends(require_admin)):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    database.delete_scan(scan_id)
    return {"status": "deleted"}


@app.delete("/history")
async def delete_all_history(user: str = Depends(require_admin)):
    count = database.delete_all_scans()
    return {"status": "deleted", "count": count}


@app.get("/about", response_class=HTMLResponse)
async def about_page():
    """Отдельная страница «О проекте» — статический HTML в корне."""
    return FileResponse("about.html", media_type="text/html")


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


if __name__ == "__main__":
    print("DevSecOps Scanner")
    print("  Интерфейс: http://127.0.0.1:8001")
    print("  Ctrl+C для остановки")
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")