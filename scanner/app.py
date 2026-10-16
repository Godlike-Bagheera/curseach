"""Сборка FastAPI-приложения: middleware, lifespan, подключение роутеров."""

import asyncio
import os

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import ALLOWED_HOSTS, origin_allowed
from .routes import auth, common, history, misc, scan
from .security import sessions
from .tasks import gc_loop, tasks

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(title="DevSecOps Scanner", version="1.0")

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
common.init_templates(templates)


# ---------- Middleware: CSRF-Origin + security headers ----------
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    origin = request.headers.get("origin", "")
    if origin and not origin_allowed(origin):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})

    response = await call_next(request)

    # Запрет встраивания в iframe (защита от clickjacking).
    response.headers["X-Frame-Options"] = "DENY"
    # Защита от MIME sniffing.
    response.headers["X-Content-Type-Options"] = "nosniff"
    # CSP для HTML-страниц. Разрешаем inline-скрипты/стили — они нужны
    # для шаблонов отчётов и инлайн Chart.js; внешние источники запрещены.
    if "text/html" in response.headers.get("content-type", ""):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
    return response


@app.on_event("startup")
async def startup():
    # Инициализация схемы БД (создаёт таблицу scans, если её нет).
    # Без этого сохранение результатов падало с "no such table: scans",
    # а страница истории отдавала HTTP 500.
    import database
    database.init_db()
    asyncio.create_task(gc_loop())


# ---------- Роутеры ----------
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(misc.router)


def _run_server():
    host = os.environ.get("SCANNER_HOST", "127.0.0.1")
    port = int(os.environ.get("SCANNER_PORT", "8001"))
    print("DevSecOps Scanner")
    print(f"  Интерфейс: http://{host}:{port}")
    print("  Ctrl+C для остановки")
    import uvicorn
    uvicorn.run(app, host=host, port=port)
