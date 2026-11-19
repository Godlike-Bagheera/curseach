"""Прочие роуты: about, справочник уязвимостей, healthz, favicon."""

import os

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, Response

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

router = APIRouter()


@router.get("/about")
async def about_page():
    """Отдельная страница «О проекте» — статический HTML в корне."""
    return FileResponse(os.path.join(BASE_DIR, "about.html"), media_type="text/html")


@router.get("/vulns", response_class=HTMLResponse)
async def vulns_page(request: Request):
    """Справочник популярных уязвимостей: EN + RU-название + RU-смысл. Доступен гостю."""
    from . import common
    from ..vuln_guide import build_guide
    return common.templates.TemplateResponse(request, "vulns.html", {"guide": build_guide()})


@router.get("/healthz")
async def healthz():
    """Liveness probe без авторизации — для Docker HEALTHCHECK и балансировщика."""
    return {"status": "ok"}


@router.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
