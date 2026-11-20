"""Роуты запуска сканирования, статуса и WebSocket-потока логов."""

import asyncio
import datetime
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

import checks
import report_csv
import report_xlsx

from ..config import SCAN_MAX_REQUESTS, SESSION_TTL_SECONDS
from ..reporting import render_report
from ..security import origin_allowed, require_admin, safe_host_for_filename, sessions, validate_target_url
from ..tasks import ScanRequest, ScanTask, run_scan_in_thread, tasks

router = APIRouter()


@router.get("/available-checks")
async def available_checks(user: str = Depends(require_admin)):
    return JSONResponse(checks.get_available_checks())


@router.post("/scan")
async def start_scan(req: ScanRequest, user: str = Depends(require_admin)):
    if req.mode not in ("quick", "full", "custom"):
        raise HTTPException(status_code=400, detail="Invalid mode")
    if req.mode == "custom" and not req.checks:
        raise HTTPException(status_code=400, detail="No checks selected")

    url_err = validate_target_url(req.url)
    if url_err:
        raise HTTPException(status_code=400, detail=url_err)

    task = ScanTask(
        req.url.strip(),
        mode=req.mode,
        selected_checks=req.checks,
        account1=req.account1,
        account2=req.account2,
        seed=req.seed,
    )
    task.loop = asyncio.get_running_loop()
    tasks[task.id] = task
    run_scan_in_thread(task)
    return {"task_id": task.id, "mode": task.mode}


@router.get("/status/{task_id}")
async def get_status(task_id: str, user: str = Depends(require_admin)):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.to_dict()


@router.post("/scan/{task_id}/cancel")
async def cancel_scan(task_id: str, user: str = Depends(require_admin)):
    """Кооперативная отмена: движок проверяет cancel_event перед каждым запросом."""
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail="Scan already finished")
    task.cancel_event.set()
    task.add_log("[SYS] Получен сигнал отмены — останавливаем проверки...")
    return {"status": "cancelling"}


@router.websocket("/ws/scan/{task_id}")
async def ws_scan(websocket: WebSocket, task_id: str):
    await websocket.accept()

    origin = websocket.headers.get("origin", "")
    if origin and not origin_allowed(origin):
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

    await websocket.send_json(
        {
            "type": "init",
            "logs": list(task.logs),
            "status": task.status,
            "progress": task.progress,
            "critical_count": task.critical_count,
            "high_count": task.high_count,
            "medium_count": task.medium_count,
            "low_count": task.low_count,
            "score": task.score,
            "requests_used": task.budget.used if task.budget else 0,
            "requests_max": task.budget.max_requests if task.budget else SCAN_MAX_REQUESTS,
        }
    )

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


@router.get("/report/html/{task_id}", response_class=HTMLResponse)
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


@router.get("/report/json/{task_id}")
async def get_json_report(task_id: str, user: str = Depends(require_admin)):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan not finished")
    return JSONResponse(
        {
            "scan_date": datetime.datetime.fromtimestamp(task.finished_at or time.time()).isoformat(),
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
        }
    )


@router.get("/report/csv/{task_id}")
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

    host_part = safe_host_for_filename(task.target_url)
    date_part = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"scan_{host_part}_{date_part}.csv"

    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report/xlsx/{task_id}")
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

    host_part = safe_host_for_filename(task.target_url)
    date_part = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"scan_{host_part}_{date_part}.xlsx"

    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
