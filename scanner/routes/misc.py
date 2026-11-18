"""Прочие роуты: about, favicon."""

import os

from fastapi import APIRouter
from fastapi.responses import FileResponse, Response

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

router = APIRouter()


@router.get("/about")
async def about_page():
    """Отдельная страница «О проекте» — статический HTML в корне."""
    return FileResponse(os.path.join(BASE_DIR, "about.html"), media_type="text/html")


@router.get("/healthz")
async def healthz():
    """Liveness probe без авторизации — для Docker HEALTHCHECK и балансировщика."""
    return {"status": "ok"}


@router.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
