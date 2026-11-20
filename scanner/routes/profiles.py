"""CRUD auth-профилей (сохранённые учётные данные сканирования). Только admin."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

import database

from ..security import require_admin

router = APIRouter()


class ProfileIn(BaseModel):
    name: str
    auth_type: str = "bearer"
    username: str = ""
    password: str = ""
    api_key_header: str = ""
    api_key_value: str = ""
    form_fields: dict[str, str] | None = None
    login_path: str = ""


@router.get("/auth-profiles")
async def list_profiles(user: str = Depends(require_admin)):
    return await run_in_threadpool(database.list_auth_profiles)


@router.post("/auth-profiles")
async def create_profile(p: ProfileIn, user: str = Depends(require_admin)):
    if not p.name.strip():
        raise HTTPException(status_code=400, detail="Имя профиля обязательно")
    if p.auth_type not in ("bearer", "form", "apikey"):
        raise HTTPException(status_code=400, detail="auth_type: bearer | form | apikey")
    pid = await run_in_threadpool(
        database.save_auth_profile,
        p.name.strip(),
        p.auth_type,
        p.username,
        p.password,
        p.api_key_header,
        p.api_key_value,
        p.form_fields,
        p.login_path,
    )
    return {"id": pid, "name": p.name.strip()}


@router.delete("/auth-profiles/{profile_id}")
async def delete_profile(profile_id: int, user: str = Depends(require_admin)):
    await run_in_threadpool(database.delete_auth_profile, profile_id)
    return {"status": "deleted"}
