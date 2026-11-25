"""Единое время МСК (UTC+3) и единый JSON-контракт scan_date.

Покрывает переход суток UTC->МСК, legacy-naive строки и микросекунды в БД,
суточную группировку тренда, стабильность SARIF-категории и поля JSON-ответов.
"""

import datetime
import io
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import database
import report_xlsx
import web_app
from scanner import reporting


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "msk.db"))
    database.init_db()
    return database.DB_PATH


def _insert(db_path, scan_date, target="http://t.example", critical=0, high=0, medium=0, low=0):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO scans (target_url, scan_date, critical, high, medium, low, results_json)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (target, scan_date, critical, high, medium, low, "[]"),
    )
    conn.commit()
    conn.close()


# ---------- Хелперы отображения ----------
def test_format_msk_variants():
    assert reporting.format_msk("2026-11-25T22:30:00+00:00") == "2026-11-26 01:30:00"
    assert reporting.format_msk("2026-11-25T22:30:00") == "2026-11-26 01:30:00"  # legacy naive = UTC
    assert reporting.format_msk("2026-11-25T22:30:00Z") == "2026-11-26 01:30:00"
    assert reporting.format_msk("2026-11-25T22:30:00.123456+00:00") == "2026-11-26 01:30:00"
    assert reporting.format_msk("2026-01-01") == "2026-01-01 03:00:00"
    assert reporting.format_msk("") == ""
    assert reporting.format_msk("мусор") == "мусор"


def test_utc_iso_normalizes_machine_format():
    assert reporting.utc_iso("2026-11-25T22:30:00") == "2026-11-25T22:30:00+00:00"
    assert reporting.utc_iso("2026-11-25T22:30:00Z") == "2026-11-25T22:30:00+00:00"
    assert reporting.utc_iso("2026-11-26T01:30:00+03:00") == "2026-11-25T22:30:00+00:00"
    assert reporting.utc_iso("2026-11-25T22:30:00.000001+00:00") == "2026-11-25T22:30:00.000001+00:00"
    assert reporting.utc_iso("нет даты") == ""


def test_msk_stamp_and_datetime():
    assert reporting.msk_stamp("2026-11-25T22:30:00+00:00") == "2026-11-26_01-30"
    assert reporting.msk_datetime("2026-11-25T22:30:00+00:00") == datetime.datetime(2026, 11, 26, 1, 30)


# ---------- Фильтр истории в БД ----------
def test_query_scans_msk_rollover(db):
    _insert(db, "2026-11-25T22:30:00+00:00", target="http://late")  # 01:30 МСК 26-го
    _insert(db, "2026-11-25T20:00:00+00:00", target="http://early")  # 23:00 МСК 25-го
    items, total = database.query_scans(date_from="2026-11-26", date_to="2026-11-26")
    assert total == 1 and items[0]["target_url"] == "http://late"
    items, total = database.query_scans(date_from="2026-11-25", date_to="2026-11-25")
    assert total == 1 and items[0]["target_url"] == "http://early"


def test_query_scans_legacy_naive_boundaries(db):
    # Границы суток МСК 2026-11-26: [2026-11-25T21:00:00Z, 2026-11-26T21:00:00Z).
    _insert(db, "2026-11-25T21:00:00", target="http://naive-start")  # ровно нижняя граница
    _insert(db, "2026-11-26T21:00:00", target="http://naive-end")  # ровно верхняя (исключается)
    _insert(db, "2026-11-25T21:00:00+00:00", target="http://aware-start")
    _insert(db, "2026-11-26T21:00:00+00:00", target="http://aware-end")
    _insert(db, "2026-11-25T20:59:59.999999+00:00", target="http://before")
    _insert(db, "2026-11-26T20:59:59.999999+00:00", target="http://micro-inside")
    items, total = database.query_scans(date_from="2026-11-26", date_to="2026-11-26")
    got = {s["target_url"] for s in items}
    assert total == 3
    assert got == {"http://naive-start", "http://aware-start", "http://micro-inside"}


def test_query_scans_month_and_leap_year_rollover(db):
    _insert(db, "2028-02-28T22:30:00+00:00", target="http://leap")  # 29.02.2028 01:30 МСК
    _insert(db, "2026-12-31T23:30:00+00:00", target="http://newyear")  # 01.01.2027 02:30 МСК
    assert database.query_scans(date_from="2028-02-29", date_to="2028-02-29")[1] == 1
    assert database.query_scans(date_from="2027-01-01", date_to="2027-01-01")[1] == 1
    assert database.query_scans(date_from="2028-02-28", date_to="2028-02-28")[1] == 0


# ---------- Тренд по дням ----------
def test_get_trend_groups_by_msk_day(db):
    # 23:30 МСК 25-го = 20:30 UTC 25-го; 01:30 МСК 26-го = 22:30 UTC 25-го.
    _insert(db, "2026-11-25T20:30:00+00:00", critical=1)
    _insert(db, "2026-11-25T22:30:00+00:00", high=1)
    _insert(db, "2026-11-25T20:30:00", medium=1)  # legacy naive, тот же МСК-день
    trend = {row["date"]: row for row in database.get_trend()}
    assert set(trend) == {"2026-11-25", "2026-11-26"}
    assert trend["2026-11-25"]["critical"] == 1 and trend["2026-11-25"]["medium"] == 1
    assert trend["2026-11-26"]["high"] == 1


# ---------- JSON-контракт ----------
def _login(client):
    r = client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    assert r.status_code == 303


def test_history_json_contract(db):
    _insert(db, "2026-11-25T22:30:00+00:00")
    client = TestClient(web_app.app)
    _login(client)
    row = client.get("/history").json()[0]
    assert row["scan_date"] == "2026-11-25T22:30:00+00:00"
    assert row["scan_date_display"] == "2026-11-26 01:30:00"
    one = client.get(f"/history/{row['id']}").json()
    assert one["scan_date"] == row["scan_date"] and one["scan_date_display"] == row["scan_date_display"]
    exported = json.loads(client.get(f"/history/{row['id']}/json").content)
    assert exported["scan_date"] == "2026-11-25T22:30:00+00:00"
    assert exported["scan_date_display"] == "2026-11-26 01:30:00"


def test_scan_json_payload_contract():
    scan = {
        "id": 1,
        "target_url": "http://t",
        "scan_date": "2026-11-25T22:30:00",
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "results": [],
        "mode": "quick",
    }
    payload = json.loads(reporting.scan_json_payload(scan))
    assert payload["scan_date"] == "2026-11-25T22:30:00+00:00"
    assert payload["scan_date_display"] == "2026-11-26 01:30:00"


def test_task_json_report_contract():
    from scanner.tasks import ScanTask, tasks

    t = ScanTask("http://127.0.0.1:8000", mode="quick")
    t.status = "completed"
    t.finished_at = datetime.datetime(2026, 11, 25, 22, 30, tzinfo=datetime.timezone.utc).timestamp()
    tasks[t.id] = t
    try:
        client = TestClient(web_app.app)
        _login(client)
        data = client.get(f"/report/json/{t.id}").json()
        assert data["scan_date"] == "2026-11-25T22:30:00+00:00"
        assert data["scan_date_display"] == "2026-11-26 01:30:00"
    finally:
        tasks.pop(t.id, None)


def test_diff_json_and_view_use_msk(db):
    _insert(db, "2026-11-25T22:30:00+00:00")
    _insert(db, "2026-11-25T20:00:00+00:00")
    client = TestClient(web_app.app)
    _login(client)
    ids = [s["id"] for s in client.get("/history").json()]
    a, b = ids[0], ids[1]  # b — скан в 22:30 UTC (01:30 МСК следующего дня)
    d = client.get(f"/history/diff?a={a}&b={b}").json()
    assert d["b"]["scan_date"] == "2026-11-25T22:30:00+00:00"
    assert d["b"]["scan_date_display"] == "2026-11-26 01:30:00"
    html = client.get(f"/history/diff/view?a={a}&b={b}").text
    assert "2026-11-26 01:30:00" in html and "Дата (МСК)" in html


# ---------- Экспорт истории ----------
def test_history_xlsx_converts_iso_to_msk():
    scans = [
        {
            "id": 1,
            "target_url": "http://t",
            "scan_date": "2026-11-25T22:30:00+00:00",
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
        },
        {
            "id": 2,
            "target_url": "http://t",
            "scan_date": "2026-11-26 01:30:00",
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 0,
        },
    ]
    data = report_xlsx.generate_history_xlsx(scans)
    assert data is not None
    import openpyxl

    ws = openpyxl.load_workbook(io.BytesIO(data)).active
    values = [c.value for row in ws.iter_rows() for c in row]
    assert values.count("2026-11-26 01:30:00") == 2  # ISO сконвертирован, готовая строка не тронута
    assert "Дата (МСК)" in values
    assert any(isinstance(v, str) and "Сформирован:" in v and "(МСК)" in v for v in values)


def test_webhook_summary_has_machine_and_display_date():
    from scanner.tasks import ScanTask
    from scanner.webhook import build_summary

    t = ScanTask("http://t", mode="quick")
    t.finished_at = datetime.datetime(2026, 11, 25, 22, 30, tzinfo=datetime.timezone.utc).timestamp()
    s = build_summary(t)
    assert s["scan_date"] == "2026-11-25T22:30:00+00:00"
    assert s["scan_date_display"] == "2026-11-26 01:30:00"


# ---------- SARIF ----------
def test_sarif_automation_id_stable_across_runs():
    a = reporting.results_to_sarif("http://t.example:8080", "2026-11-25T22:30:00+00:00", [])
    b = reporting.results_to_sarif("http://t.example:8080", "2026-12-01T10:00:00+00:00", [])
    assert a["runs"][0]["automationDetails"]["id"] == b["runs"][0]["automationDetails"]["id"]
    assert a["runs"][0]["automationDetails"]["id"] == "devsecops/t-example-8080"
    assert a["runs"][0]["invocations"][0]["endTimeUtc"] == "2026-11-25T22:30:00Z"
    assert a["runs"][0]["invocations"][0]["properties"]["scanDateMsk"] == "2026-11-26 01:30:00"
    other = reporting.results_to_sarif("http://other.example", "2026-11-25T22:30:00+00:00", [])
    assert other["runs"][0]["automationDetails"]["id"] != a["runs"][0]["automationDetails"]["id"]
