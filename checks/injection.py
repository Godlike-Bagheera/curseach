"""Инъекции: SQL (error/boolean/time), OS command, утечка через ошибки.

Полное покрытие OpenAPI: path/query/body-параметры, методы
GET/POST/PUT/PATCH/DELETE. Поверхности строятся в checks.surface.
"""

import asyncio
import hashlib
import re
import time

from .base import SQL_ERROR_PATTERNS, ScanContext, _body, ev
from .descriptions import get_vuln_info
from .surface import Surface, build_surfaces, probe

_SQLI_ERROR_PAYLOADS = ["'", '"', "1'", '1"', "1')", "1'))"]


def _mk(
    s: Surface,
    kind: str,
    name: str,
    level: str,
    desc: str,
    evidence: dict | None,
    confidence: str,
    vtype: str = "SQL Injection",
) -> dict:
    return {
        "level": level,
        "type": vtype,
        "endpoint": s.path,
        "method": s.method.upper(),
        "param": f"{kind}:{name}",
        "desc": desc,
        "details": get_vuln_info(vtype),
        "confidence": confidence,
        "evidence": evidence,
    }


async def _probe_param(ctx: ScanContext, s: Surface, kind: str, name: str, value):
    if kind == "path":
        return await probe(ctx, s, path_over={name: value})
    if kind == "query":
        return await probe(ctx, s, query_over={name: value})
    return await probe(ctx, s, body_over={name: value})


def _norm_body(r) -> str:
    """Нормализует динамику (timestamps/UUID/nonce) перед хеш-сравнением."""
    try:
        text = r.text
    except (UnicodeDecodeError, LookupError):
        return ""
    text = re.sub(r"\b\d{10,13}\b", "<TS>", text)
    text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>", text)
    text = re.sub(
        r'"(timestamp|ts|time|date|nonce|request_id|trace_id|expires?)"\s*:\s*("[^"]*"|\d+)',
        r'"\1":<DYN>',
        text,
        flags=re.IGNORECASE,
    )
    return text.lower()


def _norm_hash(r) -> str:
    return hashlib.md5(_norm_body(r).encode("utf-8", "replace")).hexdigest()


# ---------- SQLi: error-based ----------
async def _sqli_error_param(ctx, s, kind, name) -> dict | None:
    for payload in _SQLI_ERROR_PAYLOADS:
        r = await _probe_param(ctx, s, kind, name, payload)
        if r is None:
            continue
        body = _body(r)
        if any(p in body for p in SQL_ERROR_PATTERNS):
            return _mk(
                s,
                kind,
                name,
                "CRITICAL",
                f"Error-based SQLi: {kind}-параметр {name} (payload: {payload}, HTTP {r.status_code})",
                ev(r),
                "high",
            )
        if r.status_code == 500:
            return _mk(
                s,
                kind,
                name,
                "CRITICAL",
                f"Подозрение на SQLi: {kind}-параметр {name} — HTTP 500 на SQL-подобном payload ({payload})",
                ev(r),
                "medium",
            )
    return None


# ---------- SQLi: boolean-based ----------
async def _sqli_boolean_param(ctx, s, kind, name) -> dict | None:
    r_base = await _probe_param(ctx, s, kind, name, "1")
    if r_base is None or r_base.status_code != 200:
        return None
    r_true = await _probe_param(ctx, s, kind, name, "1 AND 1=1")
    r_false = await _probe_param(ctx, s, kind, name, "1 AND 1=2")
    if r_true is None or r_false is None:
        return None
    if r_true.status_code != 200 or r_false.status_code != 200:
        return None
    bh, th, fh = _norm_hash(r_base), _norm_hash(r_true), _norm_hash(r_false)
    if bh == th and bh != fh:
        return _mk(
            s,
            kind,
            name,
            "CRITICAL",
            f"Boolean-based SQLi: {kind}-параметр {name} (1 AND 1=1 vs 1 AND 1=2, динамика нормализована)",
            ev(r_false),
            "high",
        )
    return None


# ---------- SQLi: time-based (с перепроверкой) ----------
async def _sqli_time_param(ctx, s, kind, name) -> dict | None:
    t0 = time.perf_counter()
    r_base = await _probe_param(ctx, s, kind, name, "1")
    baseline = time.perf_counter() - t0
    if r_base is None:
        return None
    threshold = max(baseline * 2.0, baseline + 2.0)
    payloads = [
        ("1' AND SLEEP(3)--", "MySQL/MariaDB"),
        ("1'; SELECT pg_sleep(3)--", "PostgreSQL"),
        ("1'; WAITFOR DELAY '0:0:3'--", "MSSQL"),
    ]
    for payload, db_type in payloads:
        t0 = time.perf_counter()
        r = await _probe_param(ctx, s, kind, name, payload)
        elapsed = time.perf_counter() - t0
        if r is None or r.status_code >= 500 or elapsed < threshold:
            continue
        # Перепроверка вторым запросом — отсекаем случайные тормоза сети.
        t0 = time.perf_counter()
        r2 = await _probe_param(ctx, s, kind, name, payload)
        elapsed2 = time.perf_counter() - t0
        if r2 is not None and elapsed2 >= threshold:
            return _mk(
                s,
                kind,
                name,
                "CRITICAL",
                f"Time-based SQLi (подтверждено 2 запросами): {kind}-параметр {name}, {db_type}, "
                f"задержки {elapsed:.1f}s/{elapsed2:.1f}s (baseline {baseline:.1f}s)",
                ev(r2),
                "high",
            )
    return None


async def check_sqli(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    surfaces = build_surfaces(ctx, endpoints)

    async def per_surface(s: Surface) -> list[dict]:
        for kind, name in s.injectable:
            f = await _sqli_error_param(ctx, s, kind, name)
            if f is None:
                f = await _sqli_boolean_param(ctx, s, kind, name)
            if f is None:
                f = await _sqli_time_param(ctx, s, kind, name)
            if f:
                return [f]
        return []

    results = await asyncio.gather(*(per_surface(s) for s in surfaces))
    return [f for chunk in results for f in chunk]


# ---------- OS Command Injection ----------
async def check_command_injection(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    surfaces = build_surfaces(ctx, endpoints)
    payloads = [";id", "|id", "&whoami", "$(id)", "`id`"]

    async def per_surface(s: Surface) -> list[dict]:
        for kind, name in s.injectable:
            for payload in payloads:
                r = await _probe_param(ctx, s, kind, name, payload)
                if r is None:
                    continue
                body = _body(r)
                if any(sig in body for sig in ("uid=", "gid=", "root:", "windows ip")):
                    return [
                        _mk(
                            s,
                            kind,
                            name,
                            "CRITICAL",
                            f"Возможна инъекция команд ОС через {kind}-параметр {name} (payload: {payload})",
                            ev(r),
                            "high",
                            "OS Command Injection",
                        )
                    ]
        return []

    results = await asyncio.gather(*(per_surface(s) for s in surfaces))
    return [f for chunk in results for f in chunk]


# ---------- Утечка через ошибки ----------
async def check_error_leak(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    surfaces = build_surfaces(ctx, endpoints)[:8]

    async def per_surface(s: Surface) -> list[dict]:
        for kind, name in s.injectable[:1]:
            r = await _probe_param(ctx, s, kind, name, "invalid'")
            if r is None:
                continue
            body = _body(r)
            if any(k in body for k in ("traceback", "stack trace", "at line", 'file "')):
                return [
                    _mk(
                        s,
                        kind,
                        name,
                        "MEDIUM",
                        f"В ответе содержатся детали ошибки (stack trace) на {kind}-параметре {name}",
                        ev(r),
                        "high",
                        "Information Leak via Errors",
                    )
                ]
        return []

    results = await asyncio.gather(*(per_surface(s) for s in surfaces))
    return [f for chunk in results for f in chunk]
