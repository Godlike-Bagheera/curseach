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
                webhook_url TEXT DEFAULT ''
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
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date DESC)")


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
):
    scan_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
    results_json = json.dumps(results, ensure_ascii=False)
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO scans (target_url, scan_date, critical, high, medium, low, results_json, mode, partial,
                               partial_reason, endpoints_count, surfaces_count, requests_used, requests_max, webhook_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
