"""Прочие роуты: about, favicon."""

from fastapi import APIRouter
from fastapi.responses import FileResponse, Response

router = APIRouter()


@router.get("/about")
async def about_page():
    """Отдельная страница «О проекте» — статический HTML в корне."""
    return FileResponse("about.html", media_type="text/html")


@router.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
