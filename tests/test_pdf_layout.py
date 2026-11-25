"""Регресс-тесты вёрстки PDF: типы уязвимостей без подчёркивания, футер не убегает на отдельный лист."""

from __future__ import annotations

import os
import sys
import types

import pytest

from scanner import pdf

_HEAD = (
    "<html><head><style>"
    ".vuln-link{color:inherit;text-decoration:underline dotted;text-underline-offset:3px}"
    "</style></head><body>"
)
_FOOTER = (
    '<div class="doc-footer"><span>Отчёт сформирован автоматически системой DevSecOps Scanner</span>'
    "<span>2026-11-23 17:53:55</span></div>"
)


def _findings_table(rows: int) -> str:
    body = "".join(
        f'<tr><td><span class="level-badge HIGH">HIGH</span></td>'
        f'<td><a class="vuln-link" href="/vulns#sql-injection">SQL Injection #{i}</a></td>'
        f"<td><code>/api/{i}</code></td><td>desc {i}</td><td>fix {i}</td></tr>"
        for i in range(rows)
    )
    return (
        '<table class="findings-table"><thead><tr>'
        '<th style="width: 85px;">Уровень</th><th style="width: 150px;">Тип</th>'
        '<th style="width: 180px;">Эндпоинт</th><th>Описание</th><th>Рекомендация</th>'
        "</tr></thead><tbody>" + body + "</tbody></table>"
    )


def _report(rows: int = 3, footer: str = _FOOTER, toolbar: str = "") -> str:
    return _HEAD + toolbar + '<div class="page">' + _findings_table(rows) + footer + "</div></body></html>"


@pytest.fixture
def render(monkeypatch):
    """Реальный _render_pdf_sync с фейковым Chromium: возвращает HTML, который уходит в печать."""
    captured: dict[str, str] = {}

    class _Page:
        def route(self, *args, **kwargs):
            pass

        def set_content(self, doc, **kwargs):
            captured["doc"] = doc

        def pdf(self, path=None, **kwargs):
            with open(path, "wb") as f:
                f.write(b"%PDF-1.4\n")

    class _Browser:
        def new_page(self):
            return _Page()

        def close(self):
            pass

    class _P:
        chromium = types.SimpleNamespace(launch=lambda **kwargs: _Browser())

    class _Ctx:
        def __enter__(self):
            return _P()

        def __exit__(self, *args):
            return False

    pkg = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _Ctx()
    pkg.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    def _run(html: str, ctx: dict | None = None) -> str:
        pdf.html_to_pdf(html, ctx or {})
        return captured["doc"]

    return _run


def test_vuln_types_printed_without_underline(render):
    doc = render(_report())
    assert ".vuln-link { text-decoration: none !important; }" in doc
    # override идёт после стилей шаблона — гарантированно перебивает пунктир
    assert doc.index("text-decoration: none !important") > doc.index("underline dotted")


def test_pdf_tail_css_present(render):
    doc = render(_report())
    assert ".pdf-tail { page-break-inside: avoid !important; break-inside: avoid !important; }" in doc
    assert ".pdf-tail-table { margin-bottom: 0 !important; }" in doc


def test_footer_wrapped_with_last_finding(render):
    doc = render(_report(rows=3))
    assert doc.count('class="pdf-tail"') == 1
    assert doc.count('class="doc-footer"') == 1
    main, tail = doc.split('<div class="pdf-tail">', 1)
    assert "SQL Injection #0" in main
    assert "SQL Injection #1" in main
    assert "SQL Injection #2" not in main
    assert 'class="doc-footer"' not in main
    # последняя находка и футер — в одном неразрывном блоке, футер после строки
    assert "SQL Injection #2" in tail
    assert "doc-footer" in tail
    assert tail.index("SQL Injection #2") < tail.index("doc-footer")
    assert '<col style="width:85px">' in tail
    assert '<col style="width:150px">' in tail


def test_single_finding_still_keeps_footer(render):
    doc = render(_report(rows=1))
    tail = doc.split('<div class="pdf-tail">', 1)[1]
    assert "SQL Injection #0" in tail
    assert "doc-footer" in tail


def test_report_without_findings_unchanged():
    html = _HEAD + "<p>Уязвимостей не обнаружено.</p>" + _FOOTER + "</body></html>"
    assert pdf._keep_footer_with_last_row(html) == html


def test_footer_with_nested_divs_extracted_whole():
    footer = '<div class="doc-footer"><div class="left"><span>Отчёт</span></div><span>дата</span></div>'
    doc = pdf._keep_footer_with_last_row(_report(rows=2, footer=footer))
    tail = doc.split('<div class="pdf-tail">', 1)[1]
    assert footer in tail
    assert doc.count("<div") == doc.count("</div>")


def test_toolbar_with_nested_divs_removed_cleanly(render):
    toolbar = '<div class="toolbar"><div class="toolbar-buttons"><button>Скачать PDF</button></div></div>'
    doc = render(_report(rows=2, toolbar=toolbar))
    assert "toolbar-buttons" not in doc
    assert "Скачать PDF" not in doc
    # непарный </div> закрывал .page раньше времени — разметка должна остаться парной
    assert doc.count("<div") == doc.count("</div>")


def test_real_report_template_layout(render):
    jinja2 = pytest.importorskip("jinja2")
    from scanner.vuln_guide import slugify

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(pdf.BASE_DIR, "templates")),
        autoescape=jinja2.select_autoescape(["html", "htm", "xml"]),
    )
    env.filters["vuln_slug"] = slugify
    findings = [
        {
            "level": "HIGH",
            "type": "SQL Injection",
            "endpoint": f"/api/{i}",
            "desc": "desc",
            "details": {"recommendation": "fix"},
        }
        for i in range(4)
    ]
    ctx = {
        "target_url": "http://target",
        "findings": findings,
        "critical": 0,
        "high": 4,
        "medium": 0,
        "low": 0,
        "score": 40,
        "mode_ru": "ПОЛНАЯ ПРОВЕРКА",
        "scan_date": "2026-11-23 17:53:55",
        "scan_id": 123,
    }
    doc = render(env.get_template("report.html").render(**ctx), ctx)
    assert ".vuln-link { text-decoration: none !important; }" in doc
    main, tail = doc.split('<div class="pdf-tail">', 1)
    assert "/api/3" in tail and "doc-footer" in tail
    assert "<code>/api/3</code>" not in main
    assert 'class="doc-footer"' not in main
    assert doc.count("<div") == doc.count("</div>")
