"""Серверная генерация PDF через WeasyPrint (без Chromium/Playwright).

История проблемы: печать браузером (window.print()) всегда добавляет
колонтитулы (дата / заголовок вкладки / URL), если не просить пользователя
отключить их вручную; а @page margin:0, который их убирает, прижимает
контент после переноса страницы к верху листа. Замкнутого круга CSS-ом не
решается — поэтому PDF рендерится на сервере: там колонтитулов нет по
определению, а поля страницы задаются через @page и работают корректно.

WeasyPrint — чистый Python (pip install weasyprint), весит десятки МБ
вместо ~400 МБ Chromium. Диаграмма Chart.js перед конвертацией заменяется
на SVG-аналог, который WeasyPrint умеет печатать нативно.
"""

from __future__ import annotations

import html as _html
import re
from typing import List, Optional

_LEVEL_COLORS = {
    "CRITICAL": "#e5484d",
    "HIGH": "#f76b15",
    "MEDIUM": "#ffc531",
    "LOW": "#46a758",
}


def is_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


# ---------- SVG-диаграмма вместо Canvas (печатается нативно) ----------
def make_donut_svg(critical: int, high: int, medium: int, low: int,
                   size: int = 220) -> str:
    """Кольцевая диаграмма «распределение по уровням» в виде SVG."""
    parts: List[tuple] = [
        ("CRITICAL", critical), ("HIGH", high),
        ("MEDIUM", medium), ("LOW", low),
    ]
    total = sum(v for _, v in parts)
    cx = cy = size / 2
    r_out = size * 0.42
    r_in = size * 0.26
    if total == 0:
        segs = (
            f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" fill="none" '
            f'stroke="#30363d" stroke-width="{r_out - r_in:.1f}"/>'
        )
        center_label = "0"
    else:
        import math
        segs = []
        angle = -90.0  # старт сверху
        for name, val in parts:
            if val == 0:
                continue
            sweep = 360.0 * val / total
            a0 = math.radians(angle)
            a1 = math.radians(angle + sweep)
            large = 1 if sweep > 180 else 0
            if sweep >= 359.999:  # единственная категория — полное кольцо
                segs.append(
                    f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" '
                    f'fill="none" stroke="{_LEVEL_COLORS[name]}" '
                    f'stroke-width="{r_out - r_in:.1f}"/>'
                )
            else:
                x0o, y0o = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
                x1o, y1o = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
                x0i, y0i = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
                x1i, y1i = cx + r_in * math.cos(a1 and a0), cy + r_in * math.sin(a0)
                segs.append(
                    f'<path d="M {x0o:.2f} {y0o:.2f} '
                    f'A {r_out:.2f} {r_out:.2f} 0 {large} 1 {x1o:.2f} {y1o:.2f} '
                    f'L {x0i:.2f} {y0i:.2f} '
                    f'A {r_in:.2f} {r_in:.2f} 0 {large} 0 {x1i:.2f} {y1i:.2f} Z" '
                    f'fill="{_LEVEL_COLORS[name]}"/>'
                )
            angle += sweep
        center_label = str(total)
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
        f'xmlns="http://www.w3.org/2000/svg">'
        + "".join(segs) +
        f'<text x="{cx}" y="{cy - 4}" fill="#e6edf3" font-size="34" '
        f'font-family="DejaVu Sans, Arial, sans-serif" text-anchor="middle" '
        f'font-weight="bold">{center_label}</text>'
        f'<text x="{cx}" y="{cy + 18}" fill="#8b949e" font-size="12" '
        f'font-family="DejaVu Sans, Arial, sans-serif" text-anchor="middle">'
        f'всего находок</text></svg>'
    )


def make_types_bars_svg(types_data: List[dict], width: int = 640) -> str:
    """Горизонтальные полосы «находки по типам проверок» в виде SVG."""
    if not types_data:
        return ('<p style="color:#8b949e">Нет данных для диаграммы типов.</p>')
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
            f'{d["count"]} ({d["percent"]}%)</text>'
        )
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg">' + "".join(rows) + "</svg>"
    )


# ---------- Конвертация HTML-страницы отчёта в PDF ----------
_SCRIPT_RE = re.compile(r"<script\b.*?</script>", re.S | re.I)
_TOOLBAR_RE = re.compile(r'<div class="toolbar">.*?</div>', re.S)
_PAYLOAD_RE = re.compile(
    r'<script id="chart-data" type="application/json">(.*?)</script>', re.S
)


def html_to_pdf(html_str: str, ctx: dict, base_url: Optional[str] = None) -> bytes:
    """HTML строка страницы отчёта + контекст рендера -> PDF bytes.

    Canvas-диаграммы Chart.js заменяются на SVG-аналоги (WeasyPrint не
    исполняет JS), тулбар и скрипты вырезаются, @page margin:0 — поэтому
    в PDF нет ни колонтитулов браузера (их там просто нет как класс),
    ни «прилипаний»: поля листов задаёт print-CSS самого шаблона.
    """
    from weasyprint import HTML

    doc = html_str

    critical = int(ctx.get("critical", 0))
    high = int(ctx.get("high", 0))
    medium = int(ctx.get("medium", 0))
    low = int(ctx.get("low", 0))
    types = list(ctx.get("types_data") or [])
    if not any([critical, high, medium, low]) and not types:
        # fallback: парсим JSON-payload страницы (для report.html его нет)
        m = _PAYLOAD_RE.search(doc)
        if m:
            try:
                import json
                payload = json.loads(m.group(1))
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
    doc = _TOOLBAR_RE.sub("", doc)
    doc = _SCRIPT_RE.sub("", doc)

    return HTML(string=doc, base_url=base_url).write_pdf()
