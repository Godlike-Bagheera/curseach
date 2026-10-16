import sqlite3
import json
import datetime
from typing import List, Dict, Optional

DB_PATH = "scans.db"

# Сколько последних сканов отдавать в /history.
# Хватает для графика динамики, но не вешает UI при тысячах записей.
HISTORY_LIMIT_DEFAULT = 500


def init_db():
    conn = sqlite3.connect(DB_PATH)
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
    # Индекс по дате — ускоряет выборку последних сканов.
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date DESC)")
    conn.commit()
    conn.close()


def save_scan(target_url: str, critical: int, high: int, medium: int, low: int, results: List[dict]):
    scan_date = datetime.datetime.now().isoformat()
    results_json = json.dumps(results, ensure_ascii=False)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (target_url, scan_date, critical, high, medium, low, results_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (target_url, scan_date, critical, high, medium, low, results_json))
    conn.commit()
    conn.close()


def get_all_scans(limit: int = HISTORY_LIMIT_DEFAULT) -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
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
    conn.close()
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
    Используется heatmap-агрегатами и сравнением сканов.
    Сканы идут по возрастанию id (от старых к новым) — удобно для графиков.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'SELECT id, target_url, scan_date, critical, high, medium, low, results_json '
        'FROM scans ORDER BY id DESC LIMIT ?',
        (int(limit),),
    )
    rows = c.fetchall()
    conn.close()

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
    # Разворачиваем — старые слева, новые справа.
    out.reverse()
    return out


def get_scan(scan_id: int) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'SELECT id, target_url, scan_date, critical, high, medium, low, results_json '
        'FROM scans WHERE id = ?',
        (scan_id,),
    )
    row = c.fetchone()
    conn.close()
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()


def delete_all_scans() -> int:
    """Удаляет все записи из БД. Возвращает количество удалённых строк."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scans')
    count = c.fetchone()[0]
    c.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
    return count