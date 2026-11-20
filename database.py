"""
Хранилище результатов сканов (SQLite).
- Путь к БД настраивается через SCANNER_DB_PATH (для Docker/Codespaces).
- WAL + busy_timeout + межпоточный RLock — защита от "database is locked"
  при параллельной записи из скан-тредов и чтения из event-loop.
"""

import datetime
import json
import os
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get("SCANNER_DB_PATH", "scans.db")

_DB_LOCK = threading.RLock()


@contextmanager
def _db():
    """Соединение с WAL под глобальным lock'ом; commit/close автоматически."""
    with _DB_LOCK:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            yield conn
            conn.commit()
        finally:
            conn.close()


# Сколько последних сканов отдавать в /history.
HISTORY_LIMIT_DEFAULT = 500


def init_db():
    with _db() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                critical INTEGER DEFAULT 0,
                high INTEGER DEFAULT 0,
                medium INTEGER DEFAULT 0,
                low INTEGER DEFAULT 0,
                results_json TEXT NOT NULL,
                mode TEXT DEFAULT 'full',
                partial INTEGER DEFAULT 0,
                partial_reason TEXT DEFAULT '',
                endpoints_count INTEGER DEFAULT 0,
                surfaces_count INTEGER DEFAULT 0,
                requests_used INTEGER DEFAULT 0,
                requests_max INTEGER DEFAULT 0,
                webhook_url TEXT DEFAULT '',
                project_id INTEGER
            )
        """)
        c.execute("PRAGMA table_info(scans)")
        cols = [row[1] for row in c.fetchall()]
        if "high" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN high INTEGER DEFAULT 0")
        if "mode" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN mode TEXT DEFAULT 'full'")
        if "partial" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN partial INTEGER DEFAULT 0")
            c.execute("ALTER TABLE scans ADD COLUMN partial_reason TEXT DEFAULT ''")
        if "endpoints_count" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN endpoints_count INTEGER DEFAULT 0")
            c.execute("ALTER TABLE scans ADD COLUMN surfaces_count INTEGER DEFAULT 0")
            c.execute("ALTER TABLE scans ADD COLUMN requests_used INTEGER DEFAULT 0")
            c.execute("ALTER TABLE scans ADD COLUMN requests_max INTEGER DEFAULT 0")
        if "webhook_url" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN webhook_url TEXT DEFAULT ''")
        if "project_id" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN project_id INTEGER")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date DESC)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS auth_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                auth_type TEXT DEFAULT 'bearer',
                username TEXT DEFAULT '',
                password TEXT DEFAULT '',
                api_key_header TEXT DEFAULT '',
                api_key_value TEXT DEFAULT '',
                form_fields TEXT DEFAULT '',
                login_path TEXT DEFAULT ''
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                mode TEXT DEFAULT 'full',
                interval INTEGER DEFAULT 60,
                profile_id INTEGER,
                webhook_url TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                last_run REAL
            )
        """)


def save_scan(
    target_url: str,
    critical: int,
    high: int,
    medium: int,
    low: int,
    results: list[dict],
    mode: str = "full",
    partial: bool = False,
    partial_reason: str = "",
    endpoints_count: int = 0,
    surfaces_count: int = 0,
    requests_used: int = 0,
    requests_max: int = 0,
    webhook_url: str = "",
    project_id: int | None = None,
):
    scan_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
    results_json = json.dumps(results, ensure_ascii=False)
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO scans (target_url, scan_date, critical, high, medium, low, results_json, mode, partial,
                               partial_reason, endpoints_count, surfaces_count, requests_used, requests_max, webhook_url, project_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                target_url,
                scan_date,
                critical,
                high,
                medium,
                low,
                results_json,
                mode,
                int(partial),
                partial_reason,
                int(endpoints_count),
                int(surfaces_count),
                int(requests_used),
                int(requests_max),
                webhook_url,
                project_id,
            ),
        )


def get_all_scans(limit: int = HISTORY_LIMIT_DEFAULT) -> list[dict]:
    with _db() as conn:
        c = conn.cursor()
        if limit and limit > 0:
            c.execute(
                "SELECT id, target_url, scan_date, critical, high, medium, low, mode, partial, partial_reason FROM scans ORDER BY id DESC LIMIT ?",
                (int(limit),),
            )
        else:
            c.execute(
                "SELECT id, target_url, scan_date, critical, high, medium, low, mode, partial, partial_reason FROM scans ORDER BY id DESC"
            )
        rows = c.fetchall()
    return [
        {
            "id": row[0],
            "target_url": row[1],
            "scan_date": row[2],
            "critical": row[3],
            "high": row[4],
            "medium": row[5],
            "low": row[6],
            "mode": row[7] or "full",
            "partial": bool(row[8]),
            "partial_reason": row[9] or "",
        }
        for row in rows
    ]


def _safe_json_loads(raw) -> list:
    """Парсит JSON-строку из БД, возвращает [] при любой ошибке."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return parsed


def get_scans_with_results(limit: int = 20) -> list[dict]:
    """
    Возвращает последние N сканов вместе с полным списком находок.
    Сканы идут по возрастанию id (от старых к новым) — удобно для графиков.
    """
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, target_url, scan_date, critical, high, medium, low, results_json, mode, partial, partial_reason, "
            "endpoints_count, surfaces_count, requests_used, requests_max FROM scans ORDER BY id DESC LIMIT ?",
            (int(limit),),
        )
        rows = c.fetchall()

    out = []
    for row in rows:
        out.append(
            {
                "id": row[0],
                "target_url": row[1],
                "scan_date": row[2],
                "critical": row[3],
                "high": row[4],
                "medium": row[5],
                "low": row[6],
                "results": _safe_json_loads(row[7]),
                "mode": row[8] or "full",
                "partial": bool(row[9]),
                "partial_reason": row[10] or "",
                "endpoints_count": row[11] or 0,
                "surfaces_count": row[12] or 0,
                "requests_used": row[13] or 0,
                "requests_max": row[14] or 0,
            }
        )
    out.reverse()
    return out


def get_scan(scan_id: int) -> dict | None:
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, target_url, scan_date, critical, high, medium, low, results_json, mode, partial, partial_reason, "
            "endpoints_count, surfaces_count, requests_used, requests_max FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = c.fetchone()
    if row:
        return {
            "id": row[0],
            "target_url": row[1],
            "scan_date": row[2],
            "critical": row[3],
            "high": row[4],
            "medium": row[5],
            "low": row[6],
            "results": _safe_json_loads(row[7]),
            "mode": row[8] or "full",
            "partial": bool(row[9]),
            "partial_reason": row[10] or "",
            "endpoints_count": row[11] or 0,
            "surfaces_count": row[12] or 0,
            "requests_used": row[13] or 0,
            "requests_max": row[14] or 0,
        }
    return None


def delete_scan(scan_id: int):
    with _db() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def delete_all_scans() -> int:
    """Удаляет все записи из БД. Возвращает количество удалённых строк."""
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans")
        count = c.fetchone()[0]
        c.execute("DELETE FROM scans")
    return count


def query_scans(date_from=None, date_to=None, target=None, limit=50, offset=0):
    """Серверная фильтрация истории по дате (YYYY-MM-DD) и цели + пагинация.

    Возвращает (items, total): items — страница записей, total — всего под фильтром.
    """
    where = []
    params = []
    if date_from:
        where.append("substr(scan_date, 1, 10) >= ?")
        params.append(date_from)
    if date_to:
        where.append("substr(scan_date, 1, 10) <= ?")
        params.append(date_to)
    if target:
        # Экранируем LIKE-wildcards, чтобы ввод пользователя не менял семантику фильтра.
        esc = target.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append("target_url LIKE ? ESCAPE '\\'")
        params.append("%" + esc + "%")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans" + clause, params)
        total = c.fetchone()[0]
        c.execute(
            "SELECT id, target_url, scan_date, critical, high, medium, low, mode, partial, partial_reason FROM scans"
            + clause
            + " ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)],
        )
        rows = c.fetchall()
    items = [
        {
            "id": r[0],
            "target_url": r[1],
            "scan_date": r[2],
            "critical": r[3],
            "high": r[4],
            "medium": r[5],
            "low": r[6],
            "mode": r[7] or "full",
            "partial": bool(r[8]),
            "partial_reason": r[9] or "",
        }
        for r in rows
    ]
    return items, total


def prune_old_scans(days: int) -> int:
    """Retention: удаляет сканы старше N дней. Возвращает число удалённых записей.

    days <= 0 — выключено (ничего не удаляем). Включается env SCANNER_HISTORY_RETENTION_DAYS.
    """
    if days <= 0:
        return 0
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans WHERE scan_date < ?", (cutoff,))
        count = c.fetchone()[0]
        c.execute("DELETE FROM scans WHERE scan_date < ?", (cutoff,))
    return count


# ---------- Auth-профили (сохранённые учётные данные сканирования) ----------
def _profile_row(row) -> dict:
    return {
        "id": row[0],
        "name": row[1],
        "auth_type": row[2] or "bearer",
        "username": row[3] or "",
        "password": row[4] or "",
        "api_key_header": row[5] or "",
        "api_key_value": row[6] or "",
        "form_fields": _safe_json_loads(row[7]) if row[7] else {},
        "login_path": row[8] or "",
    }


def list_auth_profiles() -> list[dict]:
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, name, auth_type, username, password, api_key_header, api_key_value, form_fields, login_path FROM auth_profiles ORDER BY name"
        )
        return [_profile_row(r) for r in c.fetchall()]


def get_auth_profile(profile_id: int) -> dict | None:
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, name, auth_type, username, password, api_key_header, api_key_value, form_fields, login_path FROM auth_profiles WHERE id = ?",
            (profile_id,),
        )
        row = c.fetchone()
    return _profile_row(row) if row else None


def save_auth_profile(
    name,
    auth_type="bearer",
    username="",
    password="",
    api_key_header="",
    api_key_value="",
    form_fields=None,
    login_path="",
) -> int:
    ff = json.dumps(form_fields or {}, ensure_ascii=False)
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO auth_profiles (name, auth_type, username, password, api_key_header, api_key_value, form_fields, login_path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET auth_type=excluded.auth_type, username=excluded.username,
                   password=excluded.password, api_key_header=excluded.api_key_header, api_key_value=excluded.api_key_value,
                   form_fields=excluded.form_fields, login_path=excluded.login_path""",
            (name, auth_type, username, password, api_key_header, api_key_value, ff, login_path),
        )
        c.execute("SELECT id FROM auth_profiles WHERE name = ?", (name,))
        return c.fetchone()[0]


def delete_auth_profile(profile_id: int):
    with _db() as conn:
        conn.execute("DELETE FROM auth_profiles WHERE id = ?", (profile_id,))


def profile_to_account(p: dict) -> dict:
    """Профиль БД → поля AccountConfig."""
    return {
        "username": p.get("username") or None,
        "password": p.get("password") or None,
        "auth_type": p.get("auth_type") or "bearer",
        "api_key_header": p.get("api_key_header") or None,
        "api_key_value": p.get("api_key_value") or None,
        "form_fields": p.get("form_fields") or None,
        "login_path": p.get("login_path") or None,
    }


# ---------- Проекты (мульти-цели) ----------
def list_projects() -> list[dict]:
    with _db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM projects ORDER BY name")
        return [{"id": r[0], "name": r[1]} for r in c.fetchall()]


def create_project(name: str) -> int:
    with _db() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO projects (name) VALUES (?) ON CONFLICT(name) DO UPDATE SET name=excluded.name", (name,))
        c.execute("SELECT id FROM projects WHERE name = ?", (name,))
        return c.fetchone()[0]


def delete_project(project_id: int):
    with _db() as conn:
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        conn.execute("UPDATE scans SET project_id = NULL WHERE project_id = ?", (project_id,))


# ---------- Расписания (повторные сканы) ----------
def _schedule_row(r) -> dict:
    return {
        "id": r[0],
        "target_url": r[1],
        "mode": r[2] or "full",
        "interval": r[3] or 60,
        "profile_id": r[4],
        "webhook_url": r[5] or "",
        "enabled": bool(r[6]),
        "last_run": r[7],
    }


def list_schedules() -> list[dict]:
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, target_url, mode, interval, profile_id, webhook_url, enabled, last_run FROM schedules ORDER BY id"
        )
        return [_schedule_row(r) for r in c.fetchall()]


def create_schedule(target_url, mode="full", interval=60, profile_id=None, webhook_url="", enabled=True) -> int:
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO schedules (target_url, mode, interval, profile_id, webhook_url, enabled, last_run) VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (target_url, mode, int(interval), profile_id, webhook_url, int(enabled)),
        )
        return c.lastrowid


def delete_schedule(schedule_id: int):
    with _db() as conn:
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))


def set_schedule_enabled(schedule_id: int, enabled: bool):
    with _db() as conn:
        conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (int(enabled), schedule_id))


def mark_schedule_run(schedule_id: int, now: float):
    with _db() as conn:
        conn.execute("UPDATE schedules SET last_run = ? WHERE id = ?", (now, schedule_id))


def due_schedules(now: float) -> list[dict]:
    """Включённые расписания, у которых подошёл срок (last_run + interval <= now)."""
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, target_url, mode, interval, profile_id, webhook_url, enabled, last_run FROM schedules WHERE enabled = 1"
        )
        rows = c.fetchall()
    out = []
    for r in rows:
        last = r[7]
        if last is None or now - last >= (r[3] or 60) * 60:
            out.append(_schedule_row(r))
    return out


# ---------- Тренд по истории (агрегация по дням) ----------
def get_trend(project_id=None, limit: int = 200) -> list[dict]:
    from scanner.config import calculate_score

    where = ""
    params: list = []
    if project_id is not None:
        where = "WHERE project_id = ?"
        params.append(project_id)
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            f"SELECT substr(scan_date, 1, 10) AS d, SUM(critical), SUM(high), SUM(medium), SUM(low) "
            f"FROM scans {where} GROUP BY d ORDER BY d DESC LIMIT ?",
            params + [int(limit)],
        )
        rows = c.fetchall()
    out = []
    for d, cr, hi, me, lo in rows:
        cr, hi, me, lo = int(cr or 0), int(hi or 0), int(me or 0), int(lo or 0)
        out.append(
            {"date": d, "score": calculate_score(cr, hi, me, lo), "critical": cr, "high": hi, "medium": me, "low": lo}
        )
    out.reverse()
    return out
