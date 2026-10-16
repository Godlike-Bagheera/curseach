"""
Генерация CSV-отчёта сканера.
Изолирован от web_app.py, чтобы не путать логику HTTP и логику отчётов.
"""

import csv
import datetime
import io
from typing import Any, Dict, List


_LEVEL_RU = {
    "CRITICAL": "Критично",
    "HIGH":     "Высоко",
    "MEDIUM":   "Средне",
    "LOW":      "Низко",
}

_LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_MODE_TITLES = {
    "quick":  "Быстрая проверка",
    "full":   "Полная проверка",
    "custom": "Выборочная проверка",
}


def generate_csv(
    target_url: str,
    mode: str,
    scan_dt: datetime.datetime,
    score: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    findings: List[Dict[str, Any]],
) -> bytes:
    """
    Формирует CSV-отчёт.
    Возвращает bytes с UTF-8 BOM (для корректного открытия в Excel).
    """
    buf = io.StringIO()
    # BOM — чтобы Excel корректно открыл UTF-8
    buf.write("\ufeff")
    writer = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL)

    scan_str = scan_dt.strftime("%Y-%m-%d %H:%M:%S")

    # ---- Шапка ----
    writer.writerow(["ОТЧЁТ ОБ АУДИТЕ БЕЗОПАСНОСТИ API"])
    writer.writerow([])

    # ---- Метаданные ----
    writer.writerow(["Целевой ресурс", target_url])
    writer.writerow(["Режим сканирования", _MODE_TITLES.get(mode, "Полная проверка")])
    writer.writerow(["Дата и время", scan_str])
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
    writer.writerow(["№", "Уровень", "Тип", "Эндпоинт", "Описание", "Рекомендация"])

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _LEVEL_ORDER.get(f.get("level", "LOW"), 99),
            f.get("type", ""),
            f.get("endpoint", ""),
        ),
    )

    if not sorted_findings:
        writer.writerow(["-", "-", "-", "-", "Уязвимостей не обнаружено", "-"])
    else:
        for idx, f in enumerate(sorted_findings, start=1):
            details = f.get("details") or {}
            writer.writerow([
                idx,
                _LEVEL_RU.get(f.get("level", ""), f.get("level", "")),
                f.get("type", ""),
                f.get("endpoint", ""),
                f.get("desc", ""),
                details.get("recommendation", ""),
            ])

    writer.writerow([])
    writer.writerow(["Отчёт сформирован автоматически системой DevSecOps Scanner"])
    writer.writerow([scan_str])

    return buf.getvalue().encode("utf-8")