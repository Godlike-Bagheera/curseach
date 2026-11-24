"""Роуты логина/выхода и главная страница."""

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..config import SESSION_TTL_SECONDS, client_ip, request_is_https
from ..security import (
    authenticate,
    check_login_rate,
    create_session,
    destroy_session,
    get_current_user,
    sessions,
)
from . import common

router = APIRouter()

# Сессии, которым CRT-экран загрузки ещё не показывался:
# он появляется один раз сразу после успешного логина и больше не повторяется
# (обновление главной, возврат на неё, новые вкладки — без анимации).
_fresh_logins: set[str] = set()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session_id: str | None = Cookie(None)):
    if get_current_user(session_id):
        return RedirectResponse(url="/", status_code=303)
    return common.templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ip = client_ip(request)
    if not check_login_rate(ip):
        return common.templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Слишком много попыток. Подождите минуту."},
            status_code=429,
        )
    user = authenticate(username, password)
    if user is None:
        return common.templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Неверный логин или пароль"},
            status_code=401,
        )
    sid = create_session(user)
    _fresh_logins.add(sid)
    _fresh_logins.intersection_update(sessions)  # чистим флаги мёртвых сессий
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="session_id",
        value=sid,
        httponly=True,
        samesite="lax",
        secure=request_is_https(request),
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    return resp


@router.post("/logout")
async def logout(session_id: str | None = Cookie(None)):
    destroy_session(session_id)
    _fresh_logins.discard(session_id)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session_id", path="/")
    return resp


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session_id: str | None = Cookie(None)):
    user = get_current_user(session_id)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    # Экран загрузки — только при первом заходе после логина (одноразовый флаг)
    show_loader = session_id in _fresh_logins
    _fresh_logins.discard(session_id)
    return common.templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": user,
            "is_guest": user == "guest",
            "show_loader": show_loader,
        },
    )
