"""Регресс-тесты вёрстки PDF: шапка таблицы не теряется, футер — в полях листа."""

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
    "<span>2026-11-25 14:43:36</span></div>"
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
    assert doc.index("text-decoration: none !important") > doc.index("underline dotted")


def test_footer_in_page_margin_boxes(render):
    doc = render(_report(), {"scan_date": "2026-11-25 14:43:36"})
    assert "@bottom-left" in doc and "@bottom-right" in doc
    assert "Отчёт сформирован автоматически системой DevSecOps Scanner" in doc
    assert 'content: "2026-11-25 14:43:36"' in doc
    # в потоке документа футер скрыт: не дублируется и не создаёт страницу
    assert ".doc-footer { display: none !important; }" in doc


def test_footer_date_falls_back_to_ctx(render):
    doc = render(_HEAD + "<p>нет футера</p></body></html>", {"scan_date": "2026-01-02 03:04:05"})
    assert 'content: "2026-01-02 03:04:05"' in doc


def test_css_str_escapes_quotes():
    bs = chr(92)
    q = chr(34)
    assert pdf._css_str("a" + q + "b" + bs + "c") == "a" + bs + q + "b" + bs + bs + "c"


def test_findings_table_stays_intact(render):
    doc = render(_report(rows=3))
    # таблицу не режем: thead Chromium повторяет на каждом листе сам
    assert "pdf-tail" not in doc
    assert doc.count("<tbody>") == 1
    assert "<thead>" in doc
    for i in range(3):
        assert f"SQL Injection #{i}" in doc
    assert doc.count('class="doc-footer"') == 1


def test_toolbar_with_nested_divs_removed_cleanly(render):
    toolbar = '<div class="toolbar"><div class="toolbar-buttons"><button>Скачать PDF</button></div></div>'
    doc = render(_report(rows=2, toolbar=toolbar))
    assert "toolbar-buttons" not in doc
    assert "Скачать PDF" not in doc
    assert doc.count("<div") == doc.count("</div>")


def _env():
    jinja2 = pytest.importorskip("jinja2")
    from scanner.vuln_guide import slugify

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(pdf.BASE_DIR, "templates")),
        autoescape=jinja2.select_autoescape(["html", "htm", "xml"]),
    )
    env.filters["vuln_slug"] = slugify
    return env


def _findings(n: int) -> list[dict]:
    return [
        {
            "level": "HIGH",
            "type": "SQL Injection",
            "endpoint": f"/api/{i}",
            "desc": "desc",
            "details": {"recommendation": "fix"},
        }
        for i in range(n)
    ]


def test_real_report_template_layout(render):
    env = _env()
    ctx = {
        "target_url": "http://target",
        "findings": _findings(4),
        "critical": 0,
        "high": 4,
        "medium": 0,
        "low": 0,
        "score": 40,
        "mode_ru": "ПОЛНАЯ ПРОВЕРКА",
        "scan_date": "2026-11-25 14:43:36",
        "scan_id": 123,
    }
    doc = render(env.get_template("report.html").render(**ctx), ctx)
    assert ".vuln-link { text-decoration: none !important; }" in doc
    assert "@bottom-left" in doc and 'content: "2026-11-25 14:43:36"' in doc
    assert ".doc-footer { display: none !important; }" in doc
    assert "pdf-tail" not in doc
    assert "<thead>" in doc and "<code>/api/3</code>" in doc
    assert doc.count("<div") == doc.count("</div>")


def test_real_full_report_template_layout(render):
    from scanner.reporting import build_chart_context

    env = _env()
    scan = {
        "id": 123,
        "target_url": "http://target",
        "scan_date": "2026-11-25T14:43:36",
        "critical": 0,
        "high": 4,
        "medium": 0,
        "low": 0,
        "mode": "full",
        "results": _findings(4),
    }
    ctx = build_chart_context(scan, include_findings=True)
    doc = render(env.get_template("report_full.html").render(**ctx), ctx)
    assert ".vuln-link { text-decoration: none !important; }" in doc
    assert "@bottom-left" in doc and 'content: "2026-11-25 14:43:36"' in doc
    assert ".doc-footer { display: none !important; }" in doc
    assert "pdf-tail" not in doc
    assert "<thead>" in doc and "<code>/api/3</code>" in doc
    assert doc.count("<div") == doc.count("</div>")
