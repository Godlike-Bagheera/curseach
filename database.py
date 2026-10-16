"""
Хранилище результатов сканов (SQLite).
- Путь к БД настраивается через SCANNER_DB_PATH (для Docker/Codespaces).
- WAL + busy_timeout + межпоточный RLock — защита от "database is locked"
  при параллельной записи из скан-тредов и чтения из event-loop.
"""

import os
import sqlite3
import json
import datetime
import threading
from contextlib import contextmanager
from typing import List, Dict, Optional

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
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                critical INTEGER DEFAULT 0,
                high INTEGER DEFAULT 0,
                medium INTEGER DEFAULT 0,
                low INTEGER DEFAULT 0,
                results_json TEXT NOT NULL
            )
        ''')
        c.execute("PRAGMA table_info(scans)")
        cols = [row[1] for row in c.fetchall()]
        if "high" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN high INTEGER DEFAULT 0")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date DESC)")


def save_scan(target_url: str, critical: int, high: int, medium: int, low: int, results: List[dict]):
    scan_date = datetime.datetime.now().isoformat()
    results_json = json.dumps(results, ensure_ascii=False)
    with _db() as conn:
        conn.execute('''
            INSERT INTO scans (target_url, scan_date, critical, high, medium, low, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (target_url, scan_date, critical, high, medium, low, results_json))


def get_all_scans(limit: int = HISTORY_LIMIT_DEFAULT) -> List[dict]:
    with _db() as conn:
        c = conn.cursor()
        if limit and limit > 0:
            c.execute(
                'SELECT id, target_url, scan_date, critical, high, medium, low '
                'FROM scans ORDER BY id DESC LIMIT ?',
                (int(limit),),
            )
        else:
            c.execute(
                'SELECT id, target_url, scan_date, critical, high, medium, low '
                'FROM scans ORDER BY id DESC'
            )
        rows = c.fetchall()
    return [{
        "id": row[0],
        "target_url": row[1],
        "scan_date": row[2],
        "critical": row[3],
        "high": row[4],
        "medium": row[5],
        "low": row[6],
    } for row in rows]


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


def get_scans_with_results(limit: int = 20) -> List[dict]:
    """
    Возвращает последние N сканов вместе с полным списком находок.
    Сканы идут по возрастанию id (от старых к новым) — удобно для графиков.
    """
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            'SELECT id, target_url, scan_date, critical, high, medium, low, results_json '
            'FROM scans ORDER BY id DESC LIMIT ?',
            (int(limit),),
        )
        rows = c.fetchall()

    out = []
    for row in rows:
        out.append({
            "id": row[0],
            "target_url": row[1],
            "scan_date": row[2],
            "critical": row[3],
            "high": row[4],
            "medium": row[5],
            "low": row[6],
            "results": _safe_json_loads(row[7]),
        })
    out.reverse()
    return out


def get_scan(scan_id: int) -> Optional[dict]:
    with _db() as conn:
        c = conn.cursor()
        c.execute(
            'SELECT id, target_url, scan_date, critical, high, medium, low, results_json '
            'FROM scans WHERE id = ?',
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
        }
    return None


def delete_scan(scan_id: int):
    with _db() as conn:
        conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))


def delete_all_scans() -> int:
    """Удаляет все записи из БД. Возвращает количество удалённых строк."""
    with _db() as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM scans')
        count = c.fetchone()[0]
        c.execute('DELETE FROM scans')
    return count
