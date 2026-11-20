"""Статистика покрытия в отчётах (ROADMAP: бюджет и покрытие)."""

import os

from scanner import reporting

TPL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


def _scan(**kw):
    base = {
        "id": 1,
        "target_url": "http://t",
        "scan_date": "2026-11-20T10:00:00",
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "results": [],
    }
    base.update(kw)
    return base


def test_chart_context_coverage_keys():
    ctx = reporting.build_chart_context(
        _scan(endpoints_count=7, surfaces_count=12, requests_used=40, requests_max=1500)
    )
    assert ctx["endpoints_count"] == 7
    assert ctx["surfaces_count"] == 12
    assert ctx["requests_used"] == 40
    assert ctx["requests_max"] == 1500


def test_chart_context_coverage_defaults():
    ctx = reporting.build_chart_context(_scan())
    for k in ("endpoints_count", "surfaces_count", "requests_used", "requests_max"):
        assert ctx[k] == 0


def test_render_report_context_coverage(monkeypatch):
    captured = {}

    class Stub:
        def TemplateResponse(self, request, name, ctx):
            captured.update(ctx)
            return "ok"

    monkeypatch.setattr(reporting, "templates", Stub())
    reporting.render_report(
        None,
        "http://t",
        [],
        0,
        0,
        0,
        0,
        100,
        "full",
        "2026-01-01 00:00:00",
        endpoints_count=7,
        surfaces_count=12,
        requests_used=40,
        requests_max=1500,
    )
    assert captured["endpoints_count"] == 7
    assert captured["surfaces_count"] == 12
    assert captured["requests_used"] == 40
    assert captured["requests_max"] == 1500


def _env():
    from jinja2 import Environment, FileSystemLoader

    from scanner.vuln_guide import slugify

    env = Environment(loader=FileSystemLoader(TPL))
    env.filters["vuln_slug"] = slugify
    return env


def test_report_template_coverage_row():
    ctx = reporting.build_chart_context(
        _scan(endpoints_count=7, surfaces_count=12, requests_used=40, requests_max=1500), include_findings=True
    )
    ctx.update(source="task", scan_id=None)
    html = _env().get_template("report.html").render(**ctx)
    assert "Покрытие" in html
    assert "эндпоинтов 7" in html
    assert "запросов 40/бюджет 1500" in html


def test_report_full_template_coverage_row():
    ctx = reporting.build_chart_context(
        _scan(endpoints_count=7, surfaces_count=12, requests_used=40, requests_max=1500), include_findings=True
    )
    html = _env().get_template("report_full.html").render(**ctx)
    assert "Покрытие" in html
    assert "эндпоинтов 7" in html


def test_report_template_no_coverage_when_zero():
    ctx = reporting.build_chart_context(_scan(), include_findings=True)
    ctx.update(source="task", scan_id=None)
    html = _env().get_template("report.html").render(**ctx)
    assert "Покрытие" not in html


def test_db_coverage_roundtrip():
    import database

    database.init_db()
    database.save_scan(
        "http://cov.example", 0, 0, 0, 0, [], endpoints_count=9, surfaces_count=11, requests_used=55, requests_max=1500
    )
    latest = database.get_all_scans()[0]
    full = database.get_scan(latest["id"])
    assert full["endpoints_count"] == 9
    assert full["surfaces_count"] == 11
    assert full["requests_used"] == 55
    assert full["requests_max"] == 1500
    database.delete_scan(latest["id"])
