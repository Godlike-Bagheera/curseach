"""
Генерация CSV-отчёта сканера.
Изолирован от web_app.py, чтобы не путать логику HTTP и логику отчётов.
"""

import csv
import datetime
import io
from typing import Any

from scanner.config import LEVEL_RU_REPORT as _LEVEL_RU
from scanner.config import MODE_TITLES_REPORT as _MODE_TITLES

_LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _safe_cell(value):
    """CSV formula injection: ячейки, начинающиеся с = + - @ (и TAB/CR),
    могут исполниться Excel как формула. Экранируем ведущим апострофом."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


class _SafeWriter:
    def __init__(self, writer):
        self._writer = writer

    def writerow(self, row):
        self._writer.writerow([_safe_cell(c) for c in row])


def generate_csv(
    target_url: str,
    mode: str,
    scan_dt: datetime.datetime,
    score: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    findings: list[dict[str, Any]],
) -> bytes:
    """
    Формирует CSV-отчёт.
    Возвращает bytes с UTF-8 BOM (для корректного открытия в Excel).
    """
    buf = io.StringIO()
    # BOM — чтобы Excel корректно открыл UTF-8
    buf.write("\ufeff")
    writer = _SafeWriter(csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL))

    scan_str = scan_dt.strftime("%Y-%m-%d %H:%M:%S")

    # ---- Шапка ----
    writer.writerow(["ОТЧЁТ ОБ АУДИТЕ БЕЗОПАСНОСТИ API"])
    writer.writerow([])

    # ---- Метаданные ----
    writer.writerow(["Целевой ресурс", target_url])
    writer.writerow(["Режим сканирования", _MODE_TITLES.get(mode, "Полная проверка")])
    writer.writerow(["Дата и время (МСК)", scan_str])
    writer.writerow(["Оценка безопасности", f"{score} / 100"])
    writer.writerow([])

    # ---- Сводка ----
    writer.writerow(["Уровень", "Количество"])
    writer.writerow([_LEVEL_RU["CRITICAL"], critical])
    writer.writerow([_LEVEL_RU["HIGH"], high])
    writer.writerow([_LEVEL_RU["MEDIUM"], medium])
    writer.writerow([_LEVEL_RU["LOW"], low])
    writer.writerow(["Всего", critical + high + medium + low])
    writer.writerow([])

    # ---- Таблица находок ----
    writer.writerow(
        [
            "№",
            "Уровень",
            "Тип",
            "Метод",
            "Эндпоинт",
            "Параметр",
            "Уверенность",
            "CWE",
            "OWASP API",
            "Описание",
            "Рекомендация",
            "Evidence",
        ]
    )

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _LEVEL_ORDER.get(f.get("level", "LOW"), 99),
            f.get("type", ""),
            f.get("endpoint", ""),
        ),
    )

    if not sorted_findings:
        writer.writerow(["-", "-", "-", "-", "-", "-", "-", "-", "-", "Уязвимостей не обнаружено", "-", "-"])
    else:
        for idx, f in enumerate(sorted_findings, start=1):
            details = f.get("details") or {}
            evd = f.get("evidence") or {}
            if evd.get("osv_id"):
                ev_short = f"{evd.get('osv_id')} ({evd.get('package')}=={evd.get('version')})"
            elif evd.get("url"):
                ev_short = f"{evd.get('method', '')} {evd['url']} -> {evd.get('status', '')}"
            else:
                ev_short = ""
            writer.writerow(
                [
                    idx,
                    _LEVEL_RU.get(f.get("level", ""), f.get("level", "")),
                    f.get("type", ""),
                    f.get("method", ""),
                    f.get("endpoint", ""),
                    f.get("param", ""),
                    f.get("confidence", ""),
                    ", ".join(details.get("cwe") or []),
                    ", ".join(details.get("owasp_api") or []),
                    f.get("desc", ""),
                    details.get("recommendation", ""),
                    ev_short,
                ]
            )

    writer.writerow([])
    writer.writerow(["Отчёт сформирован автоматически системой DevSecOps Scanner"])
    writer.writerow([scan_str])

    return buf.getvalue().encode("utf-8")
