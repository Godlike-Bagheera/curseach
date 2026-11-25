"""Webhook-уведомления о завершении скана (ROADMAP: операционные фичи).

POST JSON-сводки на webhook_url цели. Таймаут + 1 повторная попытка;
ошибка доставки НИКОГДА не валит скан — результаты уже сохранены в историю.
"""

import datetime
import time

import httpx

WEBHOOK_TIMEOUT = 5.0
WEBHOOK_RETRIES = 1  # одна повторная попытка после неудачи


def build_summary(task, status: str | None = None) -> dict:
    """Короткая JSON-сводка для webhook (без находок и секретов).

    Время — тот же контракт, что и в JSON-отчётах: scan_date = aware UTC ISO
    (машинный), scan_date_display = строка МСК (отображение).
    """
    from .reporting import format_msk

    finished = datetime.datetime.fromtimestamp(task.finished_at or time.time(), datetime.timezone.utc).isoformat()
    return {
        "event": "scan.completed",
        "scan_date": finished,
        "scan_date_display": format_msk(finished),
        "task_id": task.id,
        "target_url": task.target_url,
        "mode": task.mode,
        "status": status or task.status,
        "score": task.score,
        "critical": task.critical_count,
        "high": task.high_count,
        "medium": task.medium_count,
        "low": task.low_count,
        "partial": task.partial,
        "findings_count": len(task.scan_results),
        "endpoints_count": task.endpoints_count,
        "requests_used": task.requests_used,
    }


async def send_webhook(
    url: str,
    payload: dict,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    retries: int = WEBHOOK_RETRIES,
) -> bool:
    """Доставляет сводку. True — сервер ответил (status < 500); False — не доставлено.

    Повторяет при сетевой ошибке или 5xx. Не бросает исключений.
    """
    if not url:
        return False
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT, transport=transport, follow_redirects=False) as client:
            for _ in range(max(0, retries) + 1):
                try:
                    r = await client.post(url, json=payload)
                    if r.status_code < 500:
                        return True
                except (httpx.HTTPError, ValueError):
                    pass
    except (httpx.HTTPError, ValueError):
        return False
    return False
