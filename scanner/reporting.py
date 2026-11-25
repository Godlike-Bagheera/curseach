"""Рендер отчётов, SARIF-экспорт и сборка ZIP-бандла.

PDF рендерится на сервере через Playwright/Chromium.
В ZIP кладётся настоящий report.pdf; если Playwright недоступен —
резервная инструкция по браузерной печати.
"""

import hashlib
import io
import json as _json
import os
import re
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import report_csv
import report_xlsx

from .config import LEVEL_RANK, MODE_TITLES_REPORT, PUBLIC_URL, VERSION, calculate_score

# ---------- Единое время отображения: Москва (UTC+3) ----------
# В БД время проверки хранится в aware UTC (database.save_scan) и не меняется.
# Здесь — только слой отображения: фиксированный offset +3, без zoneinfo/tzdata,
# чтобы отчёты, история и PDF показывали одну и ту же строку независимо от TZ сервера.
_MSK = timezone(timedelta(hours=3), "MSK")


def _parse_iso(value) -> datetime | None:
    """ISO-строка -> aware datetime. Naive считаем UTC, суффикс 'Z' допустим.

    None — значение не разобрали. Микросекунды (datetime.isoformat) и legacy-naive
    строки из БД поддерживаются; дата без времени трактуется как полночь UTC.
    """
    text = str(value or "").strip()
    if not text:
        return None
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def format_msk(value) -> str:
    """ISO (aware, naive=UTC, 'Z') -> 'YYYY-MM-DD HH:MM:SS' по Москве (слой отображения)."""
    dt = _parse_iso(value)
    if dt is None:
        return str(value or "")
    return dt.astimezone(_MSK).strftime("%Y-%m-%d %H:%M:%S")


def utc_iso(value) -> str:
    """ISO (aware, naive=UTC, 'Z') -> нормализованный aware UTC ISO ('+00:00').

    Единый машинный формат scan_date во всех JSON-ответах и SARIF.
    Пустая строка, если значение не разобрали.
    """
    dt = _parse_iso(value)
    return dt.astimezone(timezone.utc).isoformat() if dt is not None else ""


def msk_stamp(value=None) -> str:
    """Стампа для имён файлов: 'YYYY-MM-DD_HH-MM' МСК; value — дата проверки, иначе сейчас."""
    base = format_msk(value) if value is not None else datetime.now(_MSK).strftime("%Y-%m-%d %H:%M:%S")
    return base[:16].replace(" ", "_").replace(":", "-")


def msk_datetime(value) -> datetime:
    """ISO -> naive datetime в МСК: CSV/XLSX печатают его через strftime как есть."""
    return datetime.fromisoformat(format_msk(value))


# JinjaTemplates инжектится из scanner.app через init_templates(),
# чтобы избежать циклического импорта.
templates = None


def init_templates(tmpl) -> None:
    global templates
    templates = tmpl


# ---------- HTML-отчёт по активной задаче ----------
def render_report(
    request,
    target_url,
    results,
    critical,
    high,
    medium,
    low,
    score,
    mode,
    scan_date,
    partial=False,
    partial_reason="",
    endpoints_count=0,
    surfaces_count=0,
    requests_used=0,
    requests_max=0,
    scan_id=None,
):
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
            "scan_id": scan_id,
            "partial": partial,
            "partial_reason": partial_reason,
            "endpoints_count": endpoints_count,
            "surfaces_count": surfaces_count,
            "requests_used": requests_used,
            "requests_max": requests_max,
        },
    )


# ---------- Контекст для chart.html / report_full.html ----------
def build_chart_context(scan: dict, include_findings: bool = False) -> dict:
    results = scan.get("results") or []

    by_type: dict[str, int] = {}
    by_type_level: dict[str, str] = {}
    for f in results:
        t = f.get("type", "Unknown")
        lvl = f.get("level", "LOW")
        by_type[t] = by_type.get(t, 0) + 1
        if t not in by_type_level or LEVEL_RANK.get(lvl, 99) < LEVEL_RANK.get(by_type_level[t], 99):
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
        "partial": scan.get("partial", False),
        "partial_reason": scan.get("partial_reason", ""),
        "scan_id": scan["id"],
        "target_url": scan["target_url"],
        "scan_date": format_msk(scan["scan_date"]),
        "critical": scan["critical"],
        "high": scan["high"],
        "medium": scan["medium"],
        "low": scan["low"],
        "total": total,
        "score": score,
        "types_data": types_data,
        "endpoints_count": scan.get("endpoints_count", 0),
        "surfaces_count": scan.get("surfaces_count", 0),
        "requests_used": scan.get("requests_used", 0),
        "requests_max": scan.get("requests_max", 0),
    }

    if include_findings:
        ctx["findings"] = results
        ctx["mode_ru"] = MODE_TITLES_REPORT.get(scan.get("mode") or "full", "ПОЛНАЯ ПРОВЕРКА")

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
            "static",
            "chart.umd.min.js",
        )
        with open(chart_path, encoding="utf-8") as f:
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
        # Машинный формат — aware UTC ISO (как /report/json/{task_id});
        # человекочитаемая дата МСК — отдельным полем, чтобы не ломать CI-потребителей.
        "scan_date": utc_iso(scan["scan_date"]),
        "scan_date_display": format_msk(scan["scan_date"]),
        "target": scan["target_url"],
        "mode": scan.get("mode") or "full",
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
    scan_dt = msk_datetime(scan["scan_date"])
    return report_csv.generate_csv(
        target_url=scan["target_url"],
        mode=scan.get("mode") or "full",
        scan_dt=scan_dt,
        score=score,
        critical=scan["critical"],
        high=scan["high"],
        medium=scan["medium"],
        low=scan["low"],
        findings=scan.get("results") or [],
    )


def scan_xlsx_bytes(scan: dict) -> bytes | None:
    if not report_xlsx.is_available():
        return None
    score = calculate_score(scan["critical"], scan["high"], scan["medium"], scan["low"])
    scan_dt = msk_datetime(scan["scan_date"])
    return report_xlsx.generate_xlsx(
        target_url=scan["target_url"],
        mode=scan.get("mode") or "full",
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


_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "2.0"}


def _sarif_tags(details) -> list:
    tags = ["security"]
    if isinstance(details, dict):
        tags += list(details.get("cwe") or [])
        tags += list(details.get("owasp_api") or [])
        if details.get("owasp_top10"):
            tags.append(details["owasp_top10"])
    return tags


def _sarif_uri(endpoint: str) -> str:
    """
    GitHub Code Scanning требует относительный путь (scheme file), а не
    http-URL цели. Маппим эндпоинт в псевдо-путь: /api/users/{id} -> api/users/id.
    Реальные target/endpoint/method лежат в properties находки.
    """
    ep = (endpoint or "/").lstrip("/").replace("{", "").replace("}", "")
    return ep or "root"


def _evidence_text(f: dict) -> str:
    evd = f.get("evidence") or {}
    if not isinstance(evd, dict):
        return ""
    if evd.get("osv_id"):
        fixed = ", ".join(evd.get("fixed") or []) or "—"
        return f"\n\nOSV: {evd.get('osv_id')} · {evd.get('package')}=={evd.get('version')} · fixed: {fixed}"
    if not evd.get("url"):
        return ""
    parts = [f"\n\nEvidence: {evd.get('method', '')} {evd.get('url', '')} → HTTP {evd.get('status', '')}"]
    if evd.get("request_body"):
        parts.append(f"→ {str(evd['request_body'])[:200]}")
    if evd.get("response_body"):
        parts.append(f"← {str(evd['response_body'])[:300]}")
    return "\n".join(parts)


def _sarif_automation_id(target_url: str) -> str:
    """Стабильный automationDetails.id: категория прогона не зависит от времени.

    GitHub Code Scanning использует automationDetails.id как «категорию»: если id
    меняется от скана к скану (была МСК-стампа, до неё — сырой ISO), каждый аплоад
    создаёт новую категорию и алерты прошлых прогонов не дедуплицируются с новыми.
    Поэтому id строится только из цели (host:port), а время прогона уходит
    в invocations[].endTimeUtc (UTC по спеке) + properties.scanDateMsk (отображение).
    """
    netloc = urlsplit(str(target_url or "")).netloc or str(target_url or "")
    host = netloc.rsplit("@", 1)[-1].lower()
    slug = re.sub(r"[^a-z0-9]+", "-", host).strip("-")
    return f"devsecops/{slug or 'target'}"


def results_to_sarif(target_url: str, scan_date: str, findings: list[dict]) -> dict:
    """SARIF 2.1.0: evidence редактируется, helpUri ведёт на /vulns,
    partialFingerprints и стабильный automationDetails.id дают стабильность
    алертов между сканами. Время прогона: endTimeUtc (UTC) + scanDateMsk (МСК)."""
    from checks.base import redact_evidence

    from .vuln_guide import slugify

    public_base = PUBLIC_URL or "http://127.0.0.1:8001"
    rules = {}
    results = []
    for f in findings:
        vtype = f.get("type", "Unknown")
        level = f.get("level", "LOW")
        sarif_level, _ = _SEVERITY_TO_SARIF.get(level, ("note", 0.1))
        details = f.get("details") if isinstance(f.get("details"), dict) else {}
        evd = redact_evidence(f.get("evidence"))
        f_msg = {**f, "evidence": evd}
        if vtype not in rules:
            rules[vtype] = {
                "id": vtype,
                "name": vtype,
                "shortDescription": {"text": vtype},
                "fullDescription": {"text": details.get("plain", vtype)},
                "helpUri": f"{public_base}/vulns#{slugify(vtype)}",
                "defaultConfiguration": {"level": sarif_level},
                "properties": {"tags": _sarif_tags(details), "security-severity": _SECURITY_SEVERITY.get(level, "2.0")},
            }
        props = {
            "confidence": f.get("confidence", "medium"),
            "tags": _sarif_tags(details),
            "security-severity": _SECURITY_SEVERITY.get(level, "2.0"),
        }
        if f.get("method"):
            props["method"] = f["method"]
        if f.get("param"):
            props["param"] = f["param"]
        if evd:
            props["evidence"] = evd
        props["targetUrl"] = target_url
        props["endpoint"] = f.get("endpoint", "")
        fingerprint = hashlib.sha256(
            "|".join([vtype, f.get("endpoint", ""), f.get("param", ""), f.get("method", "")]).encode("utf-8")
        ).hexdigest()
        results.append(
            {
                "ruleId": vtype,
                "level": sarif_level,
                "message": {"text": f.get("desc", "") + _evidence_text(f_msg)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": _sarif_uri(f.get("endpoint", ""))}}}],
                "partialFingerprints": {"scannerFinding/v1": fingerprint},
                "properties": props,
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "DevSecOps Scanner", "version": VERSION, "rules": list(rules.values())}},
                "columnKind": "utf16CodeUnits",
                "results": results,
                "automationDetails": {"id": _sarif_automation_id(target_url)},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        # SARIF требует UTC-время с суффиксом Z; МСК — только в properties.
                        "endTimeUtc": (utc_iso(scan_date) or datetime.now(timezone.utc).isoformat()).replace(
                            "+00:00", "Z"
                        ),
                        "properties": {"scanDateMsk": format_msk(scan_date)},
                    }
                ],
            }
        ],
    }


# ---------- ZIP-бандл ----------
def build_scan_bundle(scan: dict, host_part: str) -> tuple:
    """
    Собирает ZIP: HTML (инлайн Chart.js), JSON, CSV, XLSX, SARIF и
    серверный PDF (Playwright). Если Playwright недоступен — вместо PDF
    кладётся инструкция по браузерной печати. Возвращает (zip_bytes, zip_filename).
    """
    html_ctx = build_chart_context(scan, include_findings=True)
    html_str = templates.get_template("report_full.html").render(html_ctx)
    html_str = inline_chartjs(html_str)
    html_bytes = html_str.encode("utf-8")

    json_bytes = scan_json_payload(scan)
    csv_bytes = scan_csv_bytes(scan)
    xlsx_bytes = scan_xlsx_bytes(scan)

    sarif = results_to_sarif(scan["target_url"], scan["scan_date"], scan.get("results") or [])
    sarif_bytes = _json.dumps(sarif, ensure_ascii=False, indent=2).encode("utf-8")

    scan_id = scan["id"]
    pdf_bytes = None
    try:
        from . import pdf as pdf_mod

        if pdf_mod.is_available():
            pdf_ctx = build_chart_context(scan, include_findings=True)
            pdf_html = templates.get_template("report_full.html").render(**pdf_ctx)
            pdf_bytes = pdf_mod.html_to_pdf(pdf_html, pdf_ctx)
    except Exception:
        pdf_bytes = None

    print_html = (
        "<!doctype html><meta charset='utf-8'>"
        "<h1>Как сохранить PDF</h1>"
        f"<p>Серверный PDF недоступен (Playwright не установлен). "
        f"Откройте <a href='/history/{scan_id}/full'>полный отчёт #{scan_id}</a> "
        "и нажмите «Печать (браузером)» (Ctrl+P → «Сохранить как PDF»).</p>"
    ).encode()

    date_part = msk_stamp(scan["scan_date"])
    zip_name = f"scan_{scan_id}_{host_part}_{date_part}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"scan_{scan_id}/report.html", html_bytes)
        zf.writestr(f"scan_{scan_id}/report.json", json_bytes)
        zf.writestr(f"scan_{scan_id}/report.csv", csv_bytes)
        if xlsx_bytes is not None:
            zf.writestr(f"scan_{scan_id}/report.xlsx", xlsx_bytes)
        zf.writestr(f"scan_{scan_id}/report.sarif", sarif_bytes)
        if pdf_bytes:
            zf.writestr(f"scan_{scan_id}/report.pdf", pdf_bytes)
        else:
            zf.writestr(f"scan_{scan_id}/HOW_TO_PDF.html", print_html)

    return buf.getvalue(), zip_name
