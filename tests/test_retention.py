"""Retention истории: prune_old_scans удаляет только записи старше N дней."""

import datetime

import database


def test_prune_old_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "r.db"))
    database.init_db()
    database.save_scan("http://old.example", 0, 0, 0, 0, [])
    old = (datetime.datetime.now() - datetime.timedelta(days=40)).isoformat()
    with database._db() as conn:
        conn.execute("UPDATE scans SET scan_date = ?", (old,))
    database.save_scan("http://new.example", 0, 0, 0, 0, [])
    assert database.prune_old_scans(30) == 1
    items, total = database.query_scans()
    assert total == 1 and items[0]["target_url"] == "http://new.example"
    assert database.prune_old_scans(0) == 0
