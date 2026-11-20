"""Экспорт CSV/XLSX: formula-injection и единый источник подписей."""

import datetime
import io

import report_csv
import report_xlsx
from scanner.config import LEVEL_RU_REPORT

_DT = datetime.datetime(2026, 1, 1, 12, 0, 0)
_FINDINGS = [{"level": "HIGH", "type": "X", "endpoint": "/a", "desc": "=cmd|' /C calc'!A0", "details": {}}]


def test_csv_formula_injection_sanitized():
    out = report_csv.generate_csv("http://t", "full", _DT, 50, 0, 1, 0, 0, _FINDINGS).decode("utf-8-sig")
    assert "'=cmd" in out and ";=cmd" not in out


def test_csv_uses_unified_level_labels():
    assert report_csv._LEVEL_RU is LEVEL_RU_REPORT
    out = report_csv.generate_csv("http://t", "full", _DT, 50, 0, 1, 0, 0, _FINDINGS).decode("utf-8-sig")
    assert "Высоко" in out


def test_xlsx_formula_injection_sanitized():
    data = report_xlsx.generate_xlsx("http://t", "full", _DT, 50, 0, 1, 0, 0, _FINDINGS)
    assert data is not None
    import openpyxl

    ws = openpyxl.load_workbook(io.BytesIO(data)).active
    vals = [c.value for row in ws.iter_rows() for c in row if isinstance(c.value, str)]
    assert any(v.startswith("'=cmd") for v in vals) and not any(v.startswith("=cmd") for v in vals)


def test_history_xlsx_formula_sanitized():
    scans = [
        {
            "id": 1,
            "target_url": "=cmd|' /C calc'!A0",
            "scan_date": "2026-01-01T00:00:00",
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "score": 90,
            "results": [],
            "mode": "full",
        },
        {
            "id": 2,
            "target_url": "http://ok.example",
            "scan_date": "2026-01-02T00:00:00",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "score": 100,
            "results": [],
            "mode": "quick",
        },
    ]
    data = report_xlsx.generate_history_xlsx(scans)
    assert data is not None
    import openpyxl

    ws = openpyxl.load_workbook(io.BytesIO(data)).active
    vals = [c.value for row in ws.iter_rows() for c in row if isinstance(c.value, str)]
    assert any(v.startswith("'=cmd") for v in vals)
    assert not any(v.startswith("=cmd") for v in vals)
