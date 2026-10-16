"""Роуты логина/выхода и главная страница."""

from typing import Optional

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..config import SESSION_TTL_SECONDS
from ..security import (
    authenticate,
    check_login_rate,
    create_session,
    destroy_session,
    get_current_user,
)
from . import common

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session_id: Optional[str] = Cookie(None)):
    if get_current_user(session_id):
        return RedirectResponse(url="/", status_code=303)
    return common.templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    client_ip = request.client.host if request.client else "unknown"
    if not check_login_rate(client_ip):
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
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="session_id",
        value=sid,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    return resp


@router.get("/logout")
async def logout(session_id: Optional[str] = Cookie(None)):
    destroy_session(session_id)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session_id", path="/")
    return resp


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session_id: Optional[str] = Cookie(None)):
    user = get_current_user(session_id)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return common.templates.TemplateResponse(request, "index.html", {
        "user": user,
        "is_guest": user == "guest",
    })
