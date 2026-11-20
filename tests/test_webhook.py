"""Webhook-уведомления: доставка, retry, сводка (ROADMAP: операционные фичи)."""

import asyncio
import json

import httpx

from scanner.tasks import ScanRequest, ScanTask
from scanner.webhook import build_summary, send_webhook


def test_build_summary_keys():
    t = ScanTask("http://t", mode="quick", webhook_url="https://h.example/hook")
    t.score = 80
    t.critical_count, t.high_count, t.medium_count, t.low_count = 1, 2, 3, 4
    t.scan_results = [{"type": "x"}]
    t.endpoints_count = 5
    s = build_summary(t)
    assert s["event"] == "scan.completed"
    assert s["target_url"] == "http://t"
    assert s["score"] == 80 and s["critical"] == 1 and s["high"] == 2
    assert s["findings_count"] == 1 and s["endpoints_count"] == 5
    assert "webhook_url" not in s  # адрес webhook не утекает в сводку


def test_send_webhook_success():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"ok": True})

    ok = asyncio.run(send_webhook("https://h.example/hook", {"a": 1}, transport=httpx.MockTransport(handler)))
    assert ok is True and len(calls) == 1
    assert calls[0].method == "POST"
    assert json.loads(calls[0].content) == {"a": 1}


def test_send_webhook_retry_then_success():
    n = {"c": 0}

    def handler(request):
        n["c"] += 1
        return httpx.Response(500 if n["c"] == 1 else 200)

    ok = asyncio.run(send_webhook("https://h.example/hook", {}, transport=httpx.MockTransport(handler)))
    assert ok is True and n["c"] == 2


def test_send_webhook_always_fail_one_retry():
    n = {"c": 0}

    def handler(request):
        n["c"] += 1
        return httpx.Response(503)

    ok = asyncio.run(send_webhook("https://h.example/hook", {}, transport=httpx.MockTransport(handler)))
    assert ok is False and n["c"] == 2  # ровно одна повторная попытка


def test_send_webhook_network_error_no_raise():
    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    ok = asyncio.run(send_webhook("https://h.example/hook", {}, transport=httpx.MockTransport(handler)))
    assert ok is False


def test_send_webhook_empty_url():
    assert asyncio.run(send_webhook("", {})) is False


def test_scan_request_webhook_field():
    assert ScanRequest(url="http://t", webhook_url="https://h.example/hook").webhook_url == "https://h.example/hook"
    assert ScanRequest(url="http://t").webhook_url is None


def test_scan_task_webhook_attr():
    assert ScanTask("http://t", webhook_url="https://h.example/hook").webhook_url == "https://h.example/hook"
    assert ScanTask("http://t").webhook_url is None


def test_db_webhook_stored():
    import database

    database.init_db()
    database.save_scan("http://wh.example", 0, 0, 0, 0, [], webhook_url="https://h.example/hook")
    latest = database.get_all_scans()[0]
    with database._db() as conn:
        row = conn.execute("SELECT webhook_url FROM scans WHERE id = ?", (latest["id"],)).fetchone()
    assert row[0] == "https://h.example/hook"
    database.delete_scan(latest["id"])
