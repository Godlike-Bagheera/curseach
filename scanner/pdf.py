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
_LEVEL_RU = {
    "CRITICAL": "Критические",
    "HIGH": "Высокие",
    "MEDIUM": "Средние",
    "LOW": "Низкие",
}


def _donut_segment_path(cx: float, cy: float, r_out: float, r_in: float,
                        a0_deg: float, a1_deg: float) -> str:
    """Кольцевой сегмент между углами a0..a1 (градусы, 0 = вверх, по часовой)."""
    import math

    def pt(r: float, ang_deg: float):
        a = math.radians(ang_deg - 90.0)  # смещение: старт сверху
        return cx + r * math.cos(a), cy + r * math.sin(a)

    sweep = a1_deg - a0_deg
    large = 1 if sweep > 180 else 0
    x0o, y0o = pt(r_out, a0_deg)
    x1o, y1o = pt(r_out, a1_deg)
    x1i, y1i = pt(r_in, a1_deg)
    x0i, y0i = pt(r_in, a0_deg)
    return (
        f'M {x0o:.2f} {y0o:.2f} '
        f'A {r_out:.2f} {r_out:.2f} 0 {large} 1 {x1o:.2f} {y1o:.2f} '
        f'L {x1i:.2f} {y1i:.2f} '
        f'A {r_in:.2f} {r_in:.2f} 0 {large} 0 {x0i:.2f} {y0i:.2f} Z'
    )


def make_donut_svg(critical: int, high: int, medium: int, low: int,
                   size: int = 300) -> str:
    """Кольцевая диаграмма «по уровням риска» + легенда с подписями.

    Большой круг слева, крупная легенда справа; зоны жёстко разнесены,
    пересечение текста с диаграммой невозможно. WeasyPrint рендерит SVG
    нативно, поэтому в PDF всё чётко и без Canvas.
    """
    import math

    parts = [
        ("Критические", critical, "#da3633"),
        ("Высокие", high, "#f0883e"),
        ("Средние", medium, "#d29922"),
        ("Низкие", low, "#3fb950"),
    ]
    total = sum(v for _, v, _ in parts)
    # Кольцо крупное, целиком в левой части холста; легенда — в правой.
    # Правый край кольца (cx + r_out) жёстко меньше левого края легенды.
    cx = size * 0.30                # центр круга (крупный, слева)
    cy = size / 2.0
    r_out = size * 0.30             # радиус кольца
    r_in = size * 0.18
    ring_right = cx + r_out         # ≈ 180 при size=300
    legend_x = int(ring_right + size * 0.45)  # очень большой зазор от кольца (~135px)
    width = legend_x + int(size * 0.85)       # легенда занимает всю правую половину
    height = size
    segs: List[str] = []

    if total == 0:
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" fill="none" '
            f'stroke="#d0d7de" stroke-width="{r_out - r_in:.1f}"/>'
        )
    else:
        angle = 0.0
        gap = 1.2 if len([p for p in parts if p[1] > 0]) > 1 else 0.0
        for name, val, color in parts:
            if val == 0:
                continue
            sweep = 360.0 * val / total
            a0 = angle + gap / 2
            a1 = angle + sweep - gap / 2
            if a1 <= a0:
                a1 = a0 + 0.5
            if sweep >= 359.9:  # единственная категория — полное кольцо
                segs.append(
                    f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" '
                    f'fill="none" stroke="{color}" '
                    f'stroke-width="{r_out - r_in:.1f}"/>'
                )
            else:
                segs.append(
                    f'<path d="{_donut_segment_path(cx, cy, r_out, r_in, a0, a1)}" '
                    f'fill="{color}"/>'
                )
                # число внутри сегмента — только если сектор реально широкий,
                # иначе надписи наслаиваются друг на друга
                mid = (a0 + a1) / 2.0
                arc_len = math.radians(sweep) * (r_out + r_in) / 2.0
                if sweep >= 30 and arc_len >= 20:
                    rr = (r_out + r_in) / 2.0
                    tx = cx + rr * math.cos(math.radians(mid - 90.0))
                    ty = cy + rr * math.sin(math.radians(mid - 90.0))
                    segs.append(
                        f'<text x="{tx:.1f}" y="{ty + 6:.1f}" fill="#ffffff" '
                        f'font-size="17" font-weight="bold" text-anchor="middle" '
                        f'font-family="DejaVu Sans, Arial, sans-serif">{val}</text>'
                    )
            angle += sweep

    # центр круга: итог
    center_text = (
        f'<text x="{cx}" y="{cy - 4}" fill="#1a1a1a" font-size="40" '
        f'font-weight="bold" text-anchor="middle" '
        f'font-family="DejaVu Sans, Arial, sans-serif">{total}</text>'
        f'<text x="{cx}" y="{cy + 22}" fill="#57606a" font-size="14" '
        f'text-anchor="middle" font-family="DejaVu Sans, Arial, sans-serif">'
        f'всего</text>'
    )

    # легенда: вся правая половина холста, КРУПНЫЙ текст и большой шаг строк
    lx0 = float(legend_x)
    row_h = 58                     # крупный межстрочный шаг легенды
    marker = 16                    # размер цветного маркера
    font = 17                      # крупный шрифт подписей
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
        f'xmlns="http://www.w3.org/2000/svg">'
        + "".join(segs) + center_text + "".join(legend_items) + "</svg>"
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

    # Для серверного PDF отключаем print-CSS шаблона (@media print с
    # .print-page { height: 297mm; overflow: hidden } и пр., рассчитанный
    # на браузерную печать) и включаем свой листовой режим WeasyPrint:
    # @page margin 15/14/16mm — контент никогда не пересекает границу листа,
    # колонтитулов браузера тут нет по определению, ничего не прилипает.
    override_css = (
        "<style>"
        "@page { size: A4; margin: 15mm 14mm 16mm; }"
        "html, body { background: #fff !important; color: #1a1a1a !important;"
        " -webkit-print-color-adjust: exact; print-color-adjust: exact; }"
        ".page { box-shadow: none !important; margin: 0 !important;"
        " max-width: 100% !important; padding: 0 !important; }"
        ".toolbar { display: none !important; }"
        ".print-page { height: auto !important; overflow: visible !important;"
        " page-break-after: always; break-after: page;"
        " page-break-inside: avoid; break-inside: avoid; }"
        ".print-page.last-page { page-break-after: auto; break-after: auto; }"
        ".chart-canvas canvas { display: none !important; }"
        ".chart-box svg, .types-section svg,"
        " .chart-layout svg { max-width: 100%; height: auto; }"
        "</style>"
    )
    if "</head>" in doc:
        doc = doc.replace("</head>", override_css + "</head>", 1)
    else:
        doc = override_css + doc

    doc = _TOOLBAR_RE.sub("", doc)
    doc = _SCRIPT_RE.sub("", doc)

    return HTML(string=doc, base_url=base_url).write_pdf()
