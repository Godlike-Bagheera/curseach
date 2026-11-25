"""Серверная генерация PDF через Playwright (Chromium headless).

История: печать браузером (window.print()) добавляет колонтитулы (дата,
заголовок вкладки, URL). Рендерим PDF на сервере — там колонтитулов нет по
определению, поля задаются через @page.

Playwright скачивает собственный Chromium одной командой
`python -m playwright install chromium` (≈150 МБ). Системные библиотеки
(GTK/Pango) не нужны — работает одинаково на Windows и Linux и в Docker.

Диаграмма Chart.js перед конвертацией заменяется на SVG-аналог, который
Chromium печатает нативно.
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import html as _html
import mimetypes
import os
import re
import shutil
import tempfile
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.realpath(os.path.join(BASE_DIR, "static"))

# Флаги запуска Chromium:
#  --no-sandbox — нужен в Docker под non-root (без capability SYS_ADMIN);
#  --disable-dev-shm-usage — /dev/shm в Docker маленький (64 МБ), иначе падает.
_CHROMIUM_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]


# ---------- Проверка доступности ----------

_AVAILABLE_CACHE: bool | None = None


def is_available() -> bool:
    """True, если Playwright импортируется и Chromium установлен/запускается."""
    global _AVAILABLE_CACHE
    if _AVAILABLE_CACHE is not None:
        return _AVAILABLE_CACHE
    try:
        import playwright  # noqa: F401
    except Exception:
        _AVAILABLE_CACHE = False
        return False
    try:
        if _in_running_loop():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                result = ex.submit(_probe_chromium).result(timeout=60)
        else:
            result = _probe_chromium()
    except Exception:
        result = False
    _AVAILABLE_CACHE = result
    return result


def _probe_chromium() -> bool:
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=_CHROMIUM_ARGS)
            browser.close()
        return True
    except Exception:
        return False


def _in_running_loop() -> bool:
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


# ---------- Санитизация ресурсов (anti-SSRF/LFI) ----------

def _static_path(url: str) -> str | None:
    """Локальный путь, если url ведёт в /static/ сканера; иначе None."""
    u = (url or "").strip()
    if not u or u.startswith("data:"):
        return None
    if u.startswith("file://"):
        local = os.path.realpath(urlparse(u).path)
        if local == STATIC_DIR or local.startswith(STATIC_DIR + os.sep):
            return local if os.path.isfile(local) else None
        return None
    if u.startswith("/static/"):
        rel = u[len("/static/"):]
    elif u.startswith("static/"):
        rel = u[len("static/"):]
    else:
        return None
    rel = rel.split("?")[0].split("#")[0].lstrip("/")
    candidate = os.path.realpath(os.path.join(STATIC_DIR, rel))
    if not (candidate == STATIC_DIR or candidate.startswith(STATIC_DIR + os.sep)):
        return None
    return candidate if os.path.isfile(candidate) else None


def _static_data_uri(url: str) -> str | None:
    path = _static_path(url)
    if path is None:
        return None
    mime, _ = mimetypes.guess_type(path)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return None
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:{mime or 'application/octet-stream'};base64,{b64}"


def _sanitize_css_urls(css: str) -> str:
    def _repl(m: re.Match) -> str:
        raw = m.group(1).strip().strip('"\'')
        if raw.startswith("data:"):
            return m.group(0)
        data = _static_data_uri(raw)
        if data is None:
            return "url(data:,)"
        return f"url({data})"
    return re.sub(r"url\(([^)]+)\)", _repl, css)


def _sanitize_resources(html_str: str) -> str:
    """Инлайнит static-ресурсы как data: URI, внешние ссылки обнуляет.

    Defense-in-depth против SSRF/LFI: PDF-рендерер не должен ходить в сеть
    или читать произвольные файлы. Дополнительно page.route блокирует все
    http(s)-запросы на уровне браузера.
    """
    doc = html_str

    def _inline_link(m: re.Match) -> str:
        tag = m.group(0)
        href_m = re.search(r'href="([^"]+)"', tag)
        if not href_m:
            return tag
        path = _static_path(href_m.group(1))
        if path is None:
            return ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return ""
        return f"<style>{content}</style>"

    doc = re.sub(r'<link\b[^>]*rel="stylesheet"[^>]*>', _inline_link, doc, flags=re.I)

    def _inline_img(m: re.Match) -> str:
        tag = m.group(0)
        src_m = re.search(r'src="([^"]+)"', tag)
        if not src_m:
            return tag
        data = _static_data_uri(src_m.group(1))
        if data is None:
            return tag
        return re.sub(r'src="[^"]+"', f'src="{data}"', tag)

    doc = re.sub(r"<img\b[^>]*>", _inline_img, doc, flags=re.I)

    doc = re.sub(
        r"(<style[^>]*>)(.*?)(</style>)",
        lambda m: m.group(1) + _sanitize_css_urls(m.group(2)) + m.group(3),
        doc,
        flags=re.S | re.I,
    )
    doc = re.sub(
        r'(style=")([^"]*)(")',
        lambda m: m.group(1) + _sanitize_css_urls(m.group(2)) + m.group(3),
        doc,
        flags=re.I,
    )
    return doc


# ---------- SVG-диаграмма вместо Canvas ----------

_LEVEL_COLORS = {
    "CRITICAL": "#e5484d",
    "HIGH": "#f76b15",
    "MEDIUM": "#ffc531",
    "LOW": "#46a758",
}

_LEVEL_RU = {
    "CRITICAL": "Критические",
    "HIGH": "Высокие",
    "MEDIUM": "Средние",
    "LOW": "Низкие",
}


def _donut_segment_path(cx: float, cy: float, r_out: float, r_in: float, a0_deg: float, a1_deg: float) -> str:
    """Кольцевой сегмент между углами a0..a1 (градусы, 0 = вверх, по часовой)."""
    import math

    def pt(r: float, ang_deg: float):
        a = math.radians(ang_deg - 90.0)
        return cx + r * math.cos(a), cy + r * math.sin(a)

    sweep = a1_deg - a0_deg
    large = 1 if sweep > 180 else 0
    x0o, y0o = pt(r_out, a0_deg)
    x1o, y1o = pt(r_out, a1_deg)
    x1i, y1i = pt(r_in, a1_deg)
    x0i, y0i = pt(r_in, a0_deg)
    return (
        f"M {x0o:.2f} {y0o:.2f} "
        f"A {r_out:.2f} {r_out:.2f} 0 {large} 1 {x1o:.2f} {y1o:.2f} "
        f"L {x1i:.2f} {y1i:.2f} "
        f"A {r_in:.2f} {r_in:.2f} 0 {large} 0 {x0i:.2f} {y0i:.2f} Z"
    )


def make_donut_svg(critical: int, high: int, medium: int, low: int, size: int = 300) -> str:
    """Кольцевая диаграмма «по уровням риска» + легенда с подписями."""
    import math

    parts = [
        ("Критические", critical, "#da3633"),
        ("Высокие", high, "#f0883e"),
        ("Средние", medium, "#d29922"),
        ("Низкие", low, "#3fb950"),
    ]
    total = sum(v for _, v, _ in parts)
    cx = size * 0.52
    cy = size / 2.0
    r_out = size * 0.46
    r_in = size * 0.27
    ring_right = cx + r_out
    legend_x = int(ring_right + size * 0.55)
    width = legend_x + int(size * 1.05)
    height = size
    segs: list[str] = []

    if total == 0:
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" fill="none" '
            f'stroke="#d0d7de" stroke-width="{r_out - r_in:.1f}"/>'
        )
    else:
        angle = 0.0
        gap = 1.2 if len([p for p in parts if p[1] > 0]) > 1 else 0.0
        for _name, val, color in parts:
            if val == 0:
                continue
            sweep = 360.0 * val / total
            a0 = angle + gap / 2
            a1 = angle + sweep - gap / 2
            if a1 <= a0:
                a1 = a0 + 0.5
            if sweep >= 359.9:
                segs.append(
                    f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" '
                    f'fill="none" stroke="{color}" '
                    f'stroke-width="{r_out - r_in:.1f}"/>'
                )
            else:
                segs.append(f'<path d="{_donut_segment_path(cx, cy, r_out, r_in, a0, a1)}" fill="{color}"/>')
                mid = (a0 + a1) / 2.0
                arc_len = math.radians(sweep) * (r_out + r_in) / 2.0
                rr = (r_out + r_in) / 2.0
                tx = cx + rr * math.cos(math.radians(mid - 90.0))
                ty = cy + rr * math.sin(math.radians(mid - 90.0))
                if sweep >= 24 and arc_len >= 18:
                    segs.append(
                        f'<text x="{tx:.1f}" y="{ty + 8:.1f}" fill="#ffffff" '
                        f'font-size="22" font-weight="bold" text-anchor="middle" '
                        f'font-family="DejaVu Sans, Arial, sans-serif">{val}</text>'
                    )
                elif val > 0:
                    ox = cx + (r_out + 16) * math.cos(math.radians(mid - 90.0))
                    oy = cy + (r_out + 16) * math.sin(math.radians(mid - 90.0))
                    segs.append(
                        f'<text x="{ox:.1f}" y="{oy + 7:.1f}" fill="{color}" '
                        f'font-size="20" font-weight="bold" text-anchor="middle" '
                        f'font-family="DejaVu Sans, Arial, sans-serif">{val}</text>'
                    )
            angle += sweep

    center_text = (
        f'<text x="{cx}" y="{cy - 6}" fill="#1a1a1a" font-size="54" '
        f'font-weight="bold" text-anchor="middle" '
        f'font-family="DejaVu Sans, Arial, sans-serif">{total}</text>'
        f'<text x="{cx}" y="{cy + 30}" fill="#57606a" font-size="18" '
        f'text-anchor="middle" font-family="DejaVu Sans, Arial, sans-serif">'
        f"всего</text>"
    )

    lx0 = float(legend_x)
    row_h = 62
    marker = 20
    font = 22
    rows = len(parts)
    ly0 = cy - (rows - 1) * row_h / 2.0 + font / 2.0
    legend_items = []
    for i, (name, val, color) in enumerate(parts):
        pct = round(100.0 * val / total) if total else 0
        y = ly0 + i * row_h
        value_part = f"{val} ({pct}%)" if val else "0"
        legend_items.append(
            f'<rect x="{lx0:.0f}" y="{y - marker / 2 - 2:.0f}" width="{marker}" '
            f'height="{marker}" rx="4" fill="{color}"/>'
            f'<text x="{lx0 + marker + 10:.0f}" y="{y + font / 3:.0f}" '
            f'fill="#1a1a1a" font-size="{font}" '
            f'font-family="DejaVu Sans, Arial, sans-serif">'
            f'{name}: <tspan font-weight="bold">{value_part}</tspan></text>'
        )

    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg">' + "".join(segs) + center_text + "".join(legend_items) + "</svg>"
    )


def make_types_bars_svg(types_data: list[dict], width: int = 640) -> str:
    """Горизонтальные полосы «находки по типам проверок» в виде SVG."""
    if not types_data:
        return '<p style="color:#8b949e">Нет данных для диаграммы типов.</p>'
    label_w = 240
    bar_max = width - label_w - 90
    row_h, gap = 30, 10
    max_count = max(d["count"] for d in types_data) or 1
    height = len(types_data) * (row_h + gap)
    rows = []
    for i, d in enumerate(types_data):
        y = i * (row_h + gap)
        w = max(4, round(bar_max * d["count"] / max_count))
        color = _LEVEL_COLORS.get(d.get("level", "LOW"), "#58a6ff")
        label = _html.escape(d["type"])[:44]
        rows.append(
            f'<text x="{label_w - 8}" y="{y + row_h / 2 + 4:.0f}" fill="#c9d1d9" '
            f'font-size="12" font-family="DejaVu Sans, Arial, sans-serif" '
            f'text-anchor="end">{label}</text>'
            f'<rect x="{label_w}" y="{y}" width="{w}" height="{row_h}" rx="4" '
            f'fill="{color}"/>'
            f'<text x="{label_w + w + 8}" y="{y + row_h / 2 + 4:.0f}" fill="#8b949e" '
            f'font-size="12" font-family="DejaVu Sans, Arial, sans-serif">'
            f"{d['count']} ({d['percent']}%)</text>"
        )
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg">' + "".join(rows) + "</svg>"
    )


# ---------- Конвертация HTML-страницы отчёта в PDF ----------

_SCRIPT_RE = re.compile(r"<script\b.*?</script>", re.S | re.I)
_PAYLOAD_RE = re.compile(r'<script id="chart-data" type="application/json">(.*?)</script>', re.S)
_DIV_TOKEN_RE = re.compile(r"<div\b|</div\s*>", re.I)
_SPAN_RE = re.compile(r"<span[^>]*>(.*?)</span>", re.S)
_TAG_RE = re.compile(r"<[^>]+>")

_FOOTER_LEFT_DEFAULT = "Отчёт сформирован автоматически системой DevSecOps Scanner"


def _class_open_re(tag: str, cls: str) -> re.Pattern:
    """Открывающий тег с классом cls (в т.ч. среди других классов)."""
    return re.compile(rf'<{tag}\b[^>]*class="(?:[^"]*\s)?{cls}(?:\s[^"]*)?"[^>]*>', re.I)


_TOOLBAR_OPEN_RE = _class_open_re("div", "toolbar")
_FOOTER_OPEN_RE = _class_open_re("div", "doc-footer")


def _div_block(doc: str, start: int) -> tuple[int, int] | None:
    """Границы [start, end) целого <div>…</div> с учётом вложенности.

    Ленивый `.*?</div>` обрывает блок на первом же внутреннем </div>: у тулбара
    внутри лежит .toolbar-buttons, поэтому после вырезания оставался непарный
    </div>, который закрывал родительский контейнер раньше времени.
    """
    depth = 0
    for m in _DIV_TOKEN_RE.finditer(doc, start):
        if m.group(0).lower().startswith("<div"):
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return start, m.end()
    return None


def _strip_toolbar(doc: str) -> str:
    """Вырезает тулбар целиком: кнопки не должны попадать в PDF ни текстом, ни разметкой."""
    while True:
        m = _TOOLBAR_OPEN_RE.search(doc)
        if m is None:
            return doc
        span = _div_block(doc, m.start())
        if span is None:
            return doc
        doc = doc[: span[0]] + doc[span[1] :]


def _css_str(value: str) -> str:
    """Экранирует текст для CSS-строки content: "..."."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")


def _footer_margin_boxes(doc: str, ctx: dict) -> str:
    """Колонтитул в полях листа: @bottom-left / @bottom-center / @bottom-right.

    Chromium 131+ (playwright 1.65 -> Chromium 158) рисует margin boxes В ПОЛЯХ
    листа на каждой странице: они не пересекаются с контентом, не создают
    отдельных страниц и не могут «осиротеть». Футер больше не живёт в потоке
    документа и не отрывает последнюю находку от шапки таблицы: таблица
    остаётся целой, а её thead Chromium повторяет на каждом листе сам.
    """
    left = _FOOTER_LEFT_DEFAULT
    right = str(ctx.get("scan_date") or "")
    fm = _FOOTER_OPEN_RE.search(doc)
    if fm:
        span = _div_block(doc, fm.start())
        if span is not None:
            footer_html = doc[span[0] : span[1]]
            texts = [_html.unescape(_TAG_RE.sub("", s)).strip() for s in _SPAN_RE.findall(footer_html)]
            texts = [t for t in texts if t]
            if texts:
                left = texts[0]
            if len(texts) >= 2:
                right = texts[-1]
    font = (
        "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,"
        " 'Helvetica Neue', Arial, sans-serif; font-size: 8pt; color: #888; letter-spacing: 0.3px;"
    )
    rule = "border-top: 1px solid #d0d4d9; vertical-align: top; padding-top: 3mm;"
    return (
        f'@bottom-left {{ content: "{_css_str(left)}"; {font} {rule} }}'
        f'@bottom-center {{ content: ""; {rule} }}'
        f'@bottom-right {{ content: "{_css_str(right)}"; {font} {rule} }}'
    )


def html_to_pdf(html_str: str, ctx: dict, base_url: str | None = None) -> bytes:
    """HTML строка страницы отчёта + контекст рендера -> PDF bytes.

    Canvas-диаграммы Chart.js заменяются на SVG-аналоги, тулбар и скрипты
    вырезаются, @page задаёт поля листов. Chromium рендерит всё нативно.
    """
    if _in_running_loop():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(_render_pdf_sync, html_str, ctx, base_url).result()
    return _render_pdf_sync(html_str, ctx, base_url)


def _render_pdf_sync(html_str: str, ctx: dict, base_url: str | None) -> bytes:
    from playwright.sync_api import sync_playwright

    doc = html_str

    critical = int(ctx.get("critical", 0))
    high = int(ctx.get("high", 0))
    medium = int(ctx.get("medium", 0))
    low = int(ctx.get("low", 0))
    types = list(ctx.get("types_data") or [])
    if not any([critical, high, medium, low]) and not types:
        m = _PAYLOAD_RE.search(doc)
        if m:
            try:
                import json as _json
                payload = _json.loads(m.group(1))
                critical = int(payload.get("critical", 0))
                high = int(payload.get("high", 0))
                medium = int(payload.get("medium", 0))
                low = int(payload.get("low", 0))
                types = payload.get("types_data") or []
            except Exception:
                pass

    def _svg_for(canvas_tag: str) -> str:
        if "byLevel" in canvas_tag or "donut" in canvas_tag.lower():
            return make_donut_svg(critical, high, medium, low)
        return make_types_bars_svg(types)

    doc = re.sub(r"<canvas[^>]*>", lambda m: _svg_for(m.group(0)), doc, flags=re.I)

    footer_boxes = _footer_margin_boxes(doc, ctx)

    override_css = (
        "<style>"
        "@page { size: A4; margin: 15mm 14mm 16mm; " + footer_boxes + " }"
        "html, body { background: #fff !important; color: #1a1a1a !important;"
        " -webkit-print-color-adjust: exact; print-color-adjust: exact; }"
        ".page { box-shadow: none !important; margin: 0 !important;"
        " max-width: 100% !important; padding: 0 !important; }"
        ".toolbar { display: none !important; }"
        ".print-page { height: auto !important; overflow: visible !important;"
        " page-break-after: always; break-after: page;"
        " page-break-inside: avoid; break-inside: avoid; }"
        # Последняя секция (находки + футер) выше одного листа — разрешаем
        # ей нормально делиться, иначе Chromium выталкивает её целиком и
        # футер остаётся один на чистой странице.
        ".print-page.last-page { page-break-after: auto; break-after: auto;"
        " page-break-inside: auto; break-inside: auto; }"
        ".chart-canvas canvas { display: none !important; }"
        ".chart-box svg, .types-section svg,"
        " .chart-layout svg { max-width: 100%; height: auto; }"
        # PDF: типы уязвимостей печатаем обычным текстом, без пунктира
        # (на экране подсказка-ссылка на справочник остаётся).
        ".vuln-link { text-decoration: none !important; }"
        # Футер — в полях листа (@page margin boxes выше): в потоке документа
        # прячем его, чтобы не дублировался и не создавал отдельную страницу.
        # Таблица находок остаётся целой — thead повторяется на каждом листе.
        ".doc-footer { display: none !important; }"
        "</style>"
    )
    if "</head>" in doc:
        doc = doc.replace("</head>", override_css + "</head>", 1)
    else:
        doc = override_css + doc

    doc = _strip_toolbar(doc)
    doc = _SCRIPT_RE.sub("", doc)
    doc = _sanitize_resources(doc)

    tmpdir = tempfile.mkdtemp(prefix="curseach_pdf_")
    try:
        pdf_path = os.path.join(tmpdir, "out.pdf")
        with sync_playwright() as p:
            browser = p.chromium.launch(args=_CHROMIUM_ARGS)
            try:
                page = browser.new_page()

                def _block(route):
                    url = route.request.url
                    if url.startswith(("data:", "about:", "blob:")):
                        route.continue_()
                    else:
                        route.abort()

                page.route("**/*", _block)
                page.set_content(doc, wait_until="domcontentloaded")
                page.pdf(
                    path=pdf_path,
                    format="A4",
                    print_background=True,
                    prefer_css_page_size=True,
                )
            finally:
                browser.close()
        with open(pdf_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
