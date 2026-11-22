"""Юнит-тесты инфраструктуры движка: бюджет, отмена, evidence, дедуп."""

import asyncio
import threading

import httpx
import pytest

from checks.base import (
    _EVIDENCE_LOG,
    _SCAN_CTX,
    RateLimiter,
    RequestBudget,
    ScanCancelled,
    ScanContext,
    _safe_get,
    dedup_findings,
    default_confidence,
    enrich_findings,
    pick_evidence,
)


def test_budget():
    b = RequestBudget(2)
    assert b.take() and b.take()
    assert not b.take() and b.exhausted


def test_rate_limiter_zero():
    async def run():
        rl = RateLimiter(0)
        await rl.wait()

    asyncio.run(run())


def test_dedup_keeps_best():
    fs = [
        {"type": "BAC", "endpoint": "/a", "level": "MEDIUM", "confidence": "low"},
        {"type": "BAC", "endpoint": "/a", "level": "CRITICAL", "confidence": "high"},
        {"type": "BAC", "endpoint": "/a", "param": "query:q", "level": "LOW"},
    ]
    out = dedup_findings(fs)
    assert len(out) == 2
    assert out[0]["level"] == "CRITICAL"


def test_pick_evidence_template():
    log = [{"url": "http://t/api/users/1"}, {"url": "http://t/other"}, {"url": "http://t/api/users/2"}]
    assert pick_evidence(log, "/api/users/{id}")["url"].endswith("/2")
    assert pick_evidence(log, "/other")["url"].endswith("/other")
    assert pick_evidence([], "/x") is None


def test_enrich_defaults_and_evidence():
    log = [{"url": "http://t/api/x", "status": 200}]
    fs = [{"type": "SQL Injection", "endpoint": "/api/x", "level": "CRITICAL", "desc": "d"}]
    enrich_findings(fs, log)
    assert fs[0]["confidence"] == "high" and fs[0]["evidence"]["status"] == 200
    assert default_confidence({"type": "Unknown"}) == "medium"


def test_safe_request_cancel_and_budget_and_evidence():
    def handler(request):
        return httpx.Response(200, text="ok")

    async def run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as c:
            ctx = ScanContext(target_url="http://t", client=c, anon_client=c)
            ctx.budget = RequestBudget(1)
            log = []
            t1 = _SCAN_CTX.set(ctx)
            t2 = _EVIDENCE_LOG.set(log)
            try:
                r = await _safe_get(c, "http://t/a")
                assert r is not None and r.evidence["status"] == 200 and len(log) == 1
                r2 = await _safe_get(c, "http://t/b")
                assert r2 is None and ctx.budget.exhausted
                ctx.cancel_event = threading.Event()
                ctx.cancel_event.set()
                with pytest.raises(ScanCancelled):
                    await _safe_get(c, "http://t/c")
            finally:
                _SCAN_CTX.reset(t1)
                _EVIDENCE_LOG.reset(t2)

    asyncio.run(run())
