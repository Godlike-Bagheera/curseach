"""Сборка FastAPI-приложения: middleware, lifespan, подключение роутеров."""

import asyncio
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from . import config
from .config import origin_allowed
from .routes import auth, common, history, misc, planning, profiles, scan
from .scheduler import scheduler_loop
from .security import get_current_user
from .tasks import gc_loop
from .vuln_guide import slugify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    import database

    database.init_db()
    gc_task = asyncio.create_task(gc_loop())
    sched_task = asyncio.create_task(scheduler_loop())
    try:
        yield
    finally:
        gc_task.cancel()
        sched_task.cancel()
        try:
            await gc_task
        except asyncio.CancelledError:
            pass
        try:
            await sched_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="DevSecOps Scanner", version=config.VERSION, lifespan=lifespan)


app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

templates = common.NonceTemplates(directory=os.path.join(BASE_DIR, "templates"))
common.init_templates(templates)
templates.env.filters["vuln_slug"] = slugify


# ---------- Middleware: CSRF-Origin + security headers ----------
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    origin = request.headers.get("origin", "")
    if origin and not origin_allowed(origin):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})

    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce

    response = await call_next(request)

    # Запрет встраивания в iframe (защита от clickjacking).
    response.headers["X-Frame-Options"] = "DENY"
    # Защита от MIME sniffing.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if config.HSTS_ENABLED and config.request_is_https(request):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # CSP для HTML-страниц: скрипты только свои + nonce для inline-блоков
    # (Chart.js в отчётах). Inline-стили разрешены (style-src), внешние источники запрещены.
    if "text/html" in response.headers.get("content-type", ""):
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    # Продлеваем cookie сессии, пока пользователь активен (server TTL — sliding).
    sid = request.cookies.get("session_id")
    if sid and get_current_user(sid):
        response.set_cookie(
            key="session_id",
            value=sid,
            httponly=True,
            samesite="lax",
            secure=config.request_is_https(request),
            max_age=config.SESSION_TTL_SECONDS,
            path="/",
        )
    return response


# ---------- Роутеры ----------
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(misc.router)
app.include_router(profiles.router)
app.include_router(planning.router)


def _run_server():
    host = os.environ.get("SCANNER_HOST", "127.0.0.1")
    port = int(os.environ.get("SCANNER_PORT", "8001"))
    print("DevSecOps Scanner")
    print(f"  Интерфейс: http://{host}:{port}")
    print("  Ctrl+C для остановки")
    import uvicorn

    uvicorn.run(app, host=host, port=port)
