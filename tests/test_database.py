"""Юнит-тести хранилища сканів."""
import database


def test_init_and_save_roundtrip():
    database.init_db()
    results = [{"level": "CRITICAL", "type": "SQLi", "desc": "test"}]
    before = len(database.get_all_scans())
    database.save_scan("http://localhost:8000", 1, 0, 2, 3, results)
    after = database.get_all_scans()
    assert len(after) == before + 1
    latest = after[0]
    assert latest["target_url"] == "http://localhost:8000"
    assert latest["critical"] == 1

    full = database.get_scan(latest["id"])
    assert full is not None
    assert full["results"][0]["type"] == "SQLi"


def test_delete():
    database.init_db()
    database.save_scan("http://del.me", 0, 0, 0, 0, [])
    scans = database.get_all_scans()
    target = scans[0]["id"]
    database.delete_scan(target)
    assert database.get_scan(target) is None


def test_corrupt_json_returns_empty():
    """Битый JSON в БД не должен ронять приложение."""
    import sqlite3
    database.init_db()
    with database._db() as conn:
        conn.execute(
            "INSERT INTO scans (target_url, scan_date, critical, high, medium, low, results_json)"
            " VALUES ('x', 'y', 0, 0, 0, 0, '{{{broken')"
        )
    # get_scan не должен бросать исключение
    rows = database.get_all_scans(limit=50)
    ids = [r["id"] for r in rows]
    broken_id = max(ids)
    scan = database.get_scan(broken_id)
    assert scan["results"] == []
    database.delete_scan(broken_id)
