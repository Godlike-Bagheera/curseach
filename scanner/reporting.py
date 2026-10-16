"""Рендер отчётов, SARIF-экспорт и сборка ZIP-бандла (без Playwright).

PDF больше не генерируется на сервере: вместо этого страницы отчётов
печатаются браузером пользователя (Ctrl+P / «Скачать PDF» -> window.print()),
что позволило убрать тяжёлую зависимость Playwright + Chromium (~400 МБ).
"""

import io
import json as _json
import os
import zipfile
from datetime import datetime
from typing import Dict, List, Optional

import report_csv
import report_xlsx

from .config import LEVEL_RANK, MODE_TITLES_REPORT, calculate_score

# JinjaTemplates инжектится из scanner.app через init_templates(),
# чтобы избежать циклического импорта.
templates = None


def init_templates(tmpl) -> None:
    global templates
    templates = tmpl


# ---------- HTML-отчёт по активной задаче ----------
def render_report(request, target_url, results, critical, high, medium, low,
                  score, mode, scan_date):
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "target_url": target_url,
            "findings": results,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "score": score,
            "mode_ru": MODE_TITLES_REPORT.get(mode, "ПОЛНАЯ ПРОВЕРКА"),
            "scan_date": scan_date,
            "source": "task",
            "scan_id": None,
        },
    )


# ---------- Контекст для chart.html / report_full.html ----------
def build_chart_context(scan: dict, include_findings: bool = False) -> dict:
    results = scan.get("results") or []

    by_type: Dict[str, int] = {}
    by_type_level: Dict[str, str] = {}
    for f in results:
        t = f.get("type", "Unknown")
        lvl = f.get("level", "LOW")
        by_type[t] = by_type.get(t, 0) + 1
        if t not in by_type_level or \
           LEVEL_RANK.get(lvl, 99) < LEVEL_RANK.get(by_type_level[t], 99):
            by_type_level[t] = lvl

    total = scan["critical"] + scan["high"] + scan["medium"] + scan["low"]
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])

    types_sorted = sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))
    types_data = [
        {
            "type": t,
            "level": by_type_level[t],
            "count": c,
            "percent": round(c * 100 / total, 1) if total else 0.0,
        }
        for t, c in types_sorted
    ]

    ctx = {
        "scan_id": scan["id"],
        "target_url": scan["target_url"],
        "scan_date": scan["scan_date"].replace("T", " ")[:19],
        "critical": scan["critical"],
        "high": scan["high"],
        "medium": scan["medium"],
        "low": scan["low"],
        "total": total,
        "score": score,
        "types_data": types_data,
    }

    if include_findings:
        ctx["findings"] = results
        ctx["mode_ru"] = "ПОЛНАЯ ПРОВЕРКА"

    return ctx


def inline_chartjs(html: str) -> str:
    """
    Заменяет <script src="/static/chart.umd.min.js"></script> на
    inline-версию Chart.js. Нужно для ZIP-архива: распакованный HTML
    не имеет доступа к /static/, и без этого диаграмма не отрисуется.
    Если файл Chart.js недоступен — возвращает HTML без изменений.
    """
    try:
        chart_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "static", "chart.umd.min.js",
        )
        with open(chart_path, "r", encoding="utf-8") as f:
            chart_js = f.read()
    except Exception:
        return html

    return html.replace(
        '<script src="/static/chart.umd.min.js"></script>',
        f"<script>{chart_js}</script>",
    )


# ---------- JSON / CSV / XLSX payload по данным скана ----------
def scan_json_payload(scan: dict) -> bytes:
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    payload = {
        "scan_date": scan["scan_date"],
        "target": scan["target_url"],
        "mode": "full",
        "metrics": {
            "score": score,
            "critical": scan["critical"],
            "high": scan["high"],
            "medium": scan["medium"],
            "low": scan["low"],
        },
        "findings": scan.get("results") or [],
    }
    return _json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def scan_csv_bytes(scan: dict) -> bytes:
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    scan_dt = datetime.fromisoformat(scan["scan_date"])
    return report_csv.generate_csv(
        target_url=scan["target_url"],
        mode="full",
        scan_dt=scan_dt,
        score=score,
        critical=scan["critical"],
        high=scan["high"],
        medium=scan["medium"],
        low=scan["low"],
        findings=scan.get("results") or [],
    )


def scan_xlsx_bytes(scan: dict) -> Optional[bytes]:
    if not report_xlsx.is_available():
        return None
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    scan_dt = datetime.fromisoformat(scan["scan_date"])
    return report_xlsx.generate_xlsx(
        target_url=scan["target_url"],
        mode="full",
        scan_dt=scan_dt,
        score=score,
        critical=scan["critical"],
        high=scan["high"],
        medium=scan["medium"],
        low=scan["low"],
        findings=scan.get("results") or [],
    )


# ---------- SARIF 2.1.0 (для GitHub Code Scanning) ----------
_SEVERITY_TO_SARIF = {
    "CRITICAL": ("error", 0.9),
    "HIGH": ("error", 0.7),
    "MEDIUM": ("warning", 0.5),
    "LOW": ("note", 0.2),
}


def results_to_sarif(target_url: str, scan_date: str, findings: List[dict]) -> dict:
    """Конвертирует находки сканера в формат SARIF 2.1.0."""
    rules = {}
    results = []
    for f in findings:
        vtype = f.get("type", "Unknown")
        level = f.get("level", "LOW")
        sarif_level, confidence = _SEVERITY_TO_SARIF.get(level, ("note", 0.1))
        if vtype not in rules:
            rules[vtype] = {
                "id": vtype,
                "name": vtype,
                "shortDescription": {"text": vtype},
                "fullDescription": {
                    "text": (f.get("details") or {}).get("description", vtype)
                    if isinstance(f.get("details"), dict) else vtype,
                },
                "defaultConfiguration": {"level": sarif_level},
                "properties": {"security-severity": str(round(confidence * 10, 1))},
            }
        results.append({
            "ruleId": vtype,
            "level": sarif_level,
            "message": {"text": f.get("desc", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target_url},
                },
            }],
            "properties": {"confidence": confidence},
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DevSecOps Scanner",
                    "version": "1.0",
                    "rules": list(rules.values()),
                },
            },
            "columnKind": "utf16Codes",
            "results": results,
            "automationDetails": {"id": f"devsecops/{scan_date}"},
        }],
    }


# ---------- ZIP-бандл ----------
def build_scan_bundle(scan: dict, host_part: str) -> tuple:
    """
    Собирает ZIP со всеми форматами отчёта: HTML (с инлайн Chart.js),
    JSON, CSV, XLSX, SARIF. PDF в бандле заменяется на print.html —
    страницу с инструкцией печати (браузерный Ctrl+P сохраняет PDF).
    Возвращает (zip_bytes, zip_filename).
    """
    # 1. HTML (полный — диаграмма + таблица)
    html_ctx = build_chart_context(scan, include_findings=True)
    html_str = templates.get_template("report_full.html").render(html_ctx)
    html_str = inline_chartjs(html_str)
    html_bytes = html_str.encode("utf-8")

    # 2-4. JSON / CSV / XLSX
    json_bytes = scan_json_payload(scan)
    csv_bytes = scan_csv_bytes(scan)
    xlsx_bytes = scan_xlsx_bytes(scan)

    # 5. SARIF
    sarif = results_to_sarif(scan["target_url"], scan["scan_date"], scan.get("results") or [])
    sarif_bytes = _json.dumps(sarif, ensure_ascii=False, indent=2).encode("utf-8")

    # 6. Инструкция по получению PDF через печать браузера
    scan_id = scan["id"]
    print_html = (
        "<!doctype html><meta charset='utf-8'>"
        "<h1>Как сохранить PDF</h1>"
        f"<p>Откройте <a href='/history/{scan_id}/full'>полный отчёт #{scan_id}</a> "
        "и нажмите кнопку «Скачать PDF» (или Ctrl+P → «Сохранить как PDF»). "
        "Серверная генерация PDF через Playwright упразднена.</p>"
    ).encode("utf-8")

    date_part = datetime.now().strftime("%Y-%m-%d_%H-%M")
    zip_name = f"scan_{scan_id}_{host_part}_{date_part}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"scan_{scan_id}/report.html", html_bytes)
        zf.writestr(f"scan_{scan_id}/report.json", json_bytes)
        zf.writestr(f"scan_{scan_id}/report.csv", csv_bytes)
        if xlsx_bytes is not None:
            zf.writestr(f"scan_{scan_id}/report.xlsx", xlsx_bytes)
        zf.writestr(f"scan_{scan_id}/report.sarif", sarif_bytes)
        zf.writestr(f"scan_{scan_id}/HOW_TO_PDF.html", print_html)

    return buf.getvalue(), zip_name
