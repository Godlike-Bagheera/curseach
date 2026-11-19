"""Юнит-тесты reporting.py: контекст графика и inline Chart.js."""

from scanner import reporting


def _scan():
    return {
        "id": 1,
        "target_url": "http://t",
        "scan_date": "2026-11-20T10:00:00",
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
        "results": [
            {"type": "SQLi", "level": "CRITICAL"},
            {"type": "XSS", "level": "MEDIUM"},
            {"type": "SQLi", "level": "CRITICAL"},
        ],
    }


def test_build_chart_context_counts():
    ctx = reporting.build_chart_context(_scan())
    assert ctx["total"] == 2
    assert ctx["score"] == reporting.calculate_score(1, 1, 0, 0)
    types = {t["type"]: t for t in ctx["types_data"]}
    assert types["SQLi"]["count"] == 2
    assert types["SQLi"]["level"] == "CRITICAL"
    assert types["XSS"]["count"] == 1


def test_build_chart_context_include_findings():
    ctx = reporting.build_chart_context(_scan(), include_findings=True)
    assert len(ctx["findings"]) == 3
    assert ctx["mode_ru"] == "ПОЛНАЯ ПРОВЕРКА"


def test_build_chart_context_empty():
    scan = {
        "id": 2,
        "target_url": "http://t",
        "scan_date": "2026-11-20T10:00:00",
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "results": [],
    }
    ctx = reporting.build_chart_context(scan)
    assert ctx["total"] == 0 and ctx["types_data"] == []


def test_inline_chartjs_replaces():
    html = '<html><script src="/static/chart.umd.min.js"></script></html>'
    out = reporting.inline_chartjs(html)
    assert "/static/chart.umd.min.js" not in out
    assert "<script>" in out
