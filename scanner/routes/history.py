"""Роуты истории сканов: просмотр, экспорт (HTML/JSON/CSV/XLSX/SARIF/ZIP/PDF).

PDF рендерится на сервере через WeasyPrint (/history/{id}/pdf, /full/pdf,
/view/pdf). Браузерная печать (window.print()) осталась как резерв.
"""

import datetime
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, Response

import database
import report_xlsx

from ..config import calculate_score
from ..reporting import (
    build_chart_context,
    build_scan_bundle,
    results_to_sarif,
    scan_csv_bytes,
    scan_json_payload,
)
from ..security import require_admin, safe_host_for_filename
from . import common

router = APIRouter()


async def _get_scan_or_404(scan_id: int) -> dict:
    # Синхронный SQLite не должен блокировать event loop.
    scan = await run_in_threadpool(database.get_scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ---------- Экспорт всей истории ----------
# ВАЖНО: /history/export.xlsx объявлен ДО /history/{scan_id},
# иначе "export.xlsx" парсился бы как scan_id (как в исходном web_app.py).
def _filter_scans_by_date(scans: list, date_from: str | None, date_to: str | None) -> list:
    """Фильтр сканов по дате (YYYY-MM-DD, включительно). Пустые границы — без фильтра."""
    if not date_from and not date_to:
        return scans
    out = []
    for s in scans:
        d = (s.get("scan_date") or "")[:10]
        if date_from and d < date_from:
            continue
        if date_to and d > date_to:
            continue
        out.append(s)
    return out


@router.get("/history/export.xlsx")
async def export_history_xlsx(
    user: str = Depends(require_admin),
    date_from: str | None = Query(None, alias="from"),
    date_to: str | None = Query(None, alias="to"),
):
    """Сводный XLSX по сканам истории (опционально — за период ?from=&to=)."""
    if not report_xlsx.is_available():
        raise HTTPException(
            status_code=503,
            detail="openpyxl не установлен. Выполните: pip install openpyxl",
        )

    scans = await run_in_threadpool(database.get_all_scans)
    scans = _filter_scans_by_date(scans, date_from, date_to)
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


# ---------- История (JSON) ----------
@router.get("/history")
async def get_history(
    user: str = Depends(require_admin),
    date_from: Optional[str] = Query(None, alias="from"),
    date_to: Optional[str] = Query(None, alias="to"),
    target: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """История сканов с серверной фильтрацией по дате/цели и пагинацией."""
    items, total = await run_in_threadpool(database.query_scans, date_from, date_to, target, limit, offset)
    return JSONResponse(items, headers={"X-Total-Count": str(total)})


@router.get("/history/{scan_id}")
async def get_history_item(scan_id: int, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    return JSONResponse(scan)


@router.delete("/history/{scan_id}")
async def delete_history_item(scan_id: int, user: str = Depends(require_admin)):
    await _get_scan_or_404(scan_id)
    await run_in_threadpool(database.delete_scan, scan_id)
    return {"status": "deleted"}


@router.delete("/history")
async def delete_all_history(user: str = Depends(require_admin)):
    count = await run_in_threadpool(database.delete_all_scans)
    return {"status": "deleted", "count": count}


# ---------- Страницы отчётов (HTML; серверный PDF — ниже) ----------
@router.get("/history/{scan_id}/view", response_class=HTMLResponse)
async def view_history_report(scan_id: int, request: Request, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    return common.templates.TemplateResponse(
        request,
        "report.html",
        {
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
        },
    )


@router.get("/history/{scan_id}/chart", response_class=HTMLResponse)
async def view_history_chart(scan_id: int, request: Request, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    ctx = build_chart_context(scan)
    return common.templates.TemplateResponse(request, "chart.html", ctx)


@router.get("/history/{scan_id}/full", response_class=HTMLResponse)
async def view_history_full(scan_id: int, request: Request, user: str = Depends(require_admin)):
    """Страница с объединённым отчётом: диаграмма + таблица находок."""
    scan = await _get_scan_or_404(scan_id)
    ctx = build_chart_context(scan, include_findings=True)
    return common.templates.TemplateResponse(request, "report_full.html", ctx)


# ---------- Серверный PDF (WeasyPrint, без колонтитулов браузера) ----------
def _render_pdf(template_name: str, ctx: dict, filename: str) -> Response:
    from .. import pdf as pdf_mod

    if not pdf_mod.is_available():
        raise HTTPException(
            status_code=503,
            detail="WeasyPrint не установлен. Выполните: pip install weasyprint",
        )
    html_str = common.templates.get_template(template_name).render(**ctx)
    try:
        pdf_bytes = pdf_mod.html_to_pdf(html_str, ctx)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Ошибка генерации PDF: {exc}")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/history/{scan_id}/pdf")
async def download_history_pdf(scan_id: int, user: str = Depends(require_admin)):
    """PDF страницы «Диаграмма» (SVG-диаграммы вместо Canvas)."""
    scan = await _get_scan_or_404(scan_id)
    ctx = build_chart_context(scan)
    return _render_pdf("chart.html", ctx, f"scan_{scan_id}_chart.pdf")


@router.get("/history/{scan_id}/full/pdf")
async def download_history_full_pdf(scan_id: int, user: str = Depends(require_admin)):
    """PDF полного объединённого отчёта."""
    scan = await _get_scan_or_404(scan_id)
    ctx = build_chart_context(scan, include_findings=True)
    return _render_pdf("report_full.html", ctx, f"scan_{scan_id}_full_report.pdf")


@router.get("/history/{scan_id}/view/pdf")
async def download_history_view_pdf(scan_id: int, user: str = Depends(require_admin)):
    """PDF классического отчёта по находкам."""
    scan = await _get_scan_or_404(scan_id)
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    ctx = {
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
    }
    return _render_pdf("report.html", ctx, f"scan_{scan_id}_report.pdf")


# ---------- Экспорт ----------
@router.get("/history/{scan_id}/json")
async def download_history_json(scan_id: int, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    return Response(
        content=scan_json_payload(scan),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'},
    )


@router.get("/history/{scan_id}/csv")
async def download_history_csv(scan_id: int, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    return Response(
        content=scan_csv_bytes(scan),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'},
    )


@router.get("/history/{scan_id}/sarif")
async def download_history_sarif(scan_id: int, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    sarif = results_to_sarif(scan["target_url"], scan["scan_date"], scan.get("results") or [])
    filename = f"scan_{scan_id}.sarif"
    return Response(
        content=json.dumps(sarif, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------- ZIP-архив со всеми форматами ----------
@router.get("/history/{scan_id}/bundle")
async def download_history_bundle(scan_id: int, user: str = Depends(require_admin)):
    scan = await _get_scan_or_404(scan_id)
    host_part = safe_host_for_filename(scan["target_url"])
    zip_bytes, zip_name = build_scan_bundle(scan, host_part)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
    )
