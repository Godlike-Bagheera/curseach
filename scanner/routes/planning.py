"""Проекты, расписания и тренд по истории (ROADMAP: операционные фичи). Только admin."""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

import database

from ..security import require_admin, validate_target_url

router = APIRouter()


class ProjectIn(BaseModel):
    name: str


class ScheduleIn(BaseModel):
    target_url: str
    mode: str = "full"
    interval: int = 60
    profile_id: int | None = None
    webhook_url: str = ""
    enabled: bool = True


@router.get("/projects")
async def list_projects(user: str = Depends(require_admin)):
    return await run_in_threadpool(database.list_projects)


@router.post("/projects")
async def create_project(p: ProjectIn, user: str = Depends(require_admin)):
    if not p.name.strip():
        raise HTTPException(status_code=400, detail="Имя проекта обязательно")
    pid = await run_in_threadpool(database.create_project, p.name.strip())
    return {"id": pid, "name": p.name.strip()}


@router.delete("/projects/{project_id}")
async def delete_project(project_id: int, user: str = Depends(require_admin)):
    await run_in_threadpool(database.delete_project, project_id)
    return {"status": "deleted"}


@router.get("/schedules")
async def list_schedules(user: str = Depends(require_admin)):
    return await run_in_threadpool(database.list_schedules)


@router.post("/schedules")
async def create_schedule(s: ScheduleIn, user: str = Depends(require_admin)):
    err = validate_target_url(s.target_url)
    if err:
        raise HTTPException(status_code=400, detail=err)
    if s.mode not in ("quick", "full", "custom"):
        raise HTTPException(status_code=400, detail="Invalid mode")
    if s.interval < 1:
        raise HTTPException(status_code=400, detail="interval >= 1 минута")
    sid = await run_in_threadpool(
        database.create_schedule, s.target_url, s.mode, s.interval, s.profile_id, s.webhook_url, s.enabled
    )
    return {"id": sid}


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int, user: str = Depends(require_admin)):
    await run_in_threadpool(database.delete_schedule, schedule_id)
    return {"status": "deleted"}


@router.get("/history/trend")
async def history_trend(project_id: int | None = Query(None), user: str = Depends(require_admin)):
    return await run_in_threadpool(database.get_trend, project_id)
