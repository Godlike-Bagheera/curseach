"""Инъекции: SQL, OS command, утечка через ошибки."""

import time
from typing import Dict, List, Optional

from .base import (
    ScanContext,
    _safe_get,
    _body,
    _content_hash,
    _build_path,
    SQL_ERROR_PATTERNS,
)
from .descriptions import get_vuln_info


# ================== SQL Injection ==================
_SQLI_ERROR_PAYLOADS = ["'", "\"", "1'", "1\"", "1')", "1'))"]


async def _sqli_error_based(
    client, target_url: str, ep: str, param_name: str
) -> Optional[Dict]:
    for payload in _SQLI_ERROR_PAYLOADS:
        path = _build_path(ep, param_name, payload)
        r = await _safe_get(client, f"{target_url}{path}")
        if r is None:
            continue
        body = _body(r)
        if r.status_code == 500 or any(p in body for p in SQL_ERROR_PATTERNS):
            return {
                "level": "CRITICAL",
                "type": "SQL Injection",
                "endpoint": ep,
                "desc": f"Error-based SQLi: параметр {param_name} (payload: {payload}, HTTP {r.status_code})",
                "details": get_vuln_info("SQL Injection"),
            }
    return None


async def _sqli_boolean_based(
    client, target_url: str, ep: str, param_name: str
) -> Optional[Dict]:
    base_path = ep.replace(f"{{{param_name}}}", "1")
    r_base = await _safe_get(client, f"{target_url}{base_path}")
    if r_base is None or r_base.status_code != 200:
        return None

    true_path = _build_path(ep, param_name, "1 AND 1=1")
    r_true = await _safe_get(client, f"{target_url}{true_path}")
    if r_true is None:
        return None

    false_path = _build_path(ep, param_name, "1 AND 1=2")
    r_false = await _safe_get(client, f"{target_url}{false_path}")
    if r_false is None:
        return None

    base_hash = _content_hash(r_base)
    true_hash = _content_hash(r_true)
    false_hash = _content_hash(r_false)

    if base_hash == true_hash and base_hash != false_hash:
        return {
            "level": "CRITICAL",
            "type": "SQL Injection",
            "endpoint": ep,
            "desc": f"Boolean-based SQLi: параметр {param_name} (1 AND 1=1 vs 1 AND 1=2)",
            "details": get_vuln_info("SQL Injection"),
        }
    return None


async def _sqli_time_based(
    client, target_url: str, ep: str, param_name: str
) -> Optional[Dict]:
    base_path = ep.replace(f"{{{param_name}}}", "1")
    t0 = time.perf_counter()
    r_base = await _safe_get(client, f"{target_url}{base_path}")
    baseline_time = time.perf_counter() - t0
    if r_base is None:
        return None

    SLEEP_SECONDS = 3
    THRESHOLD_REL = baseline_time * 2.0
    THRESHOLD_ABS = baseline_time + 2.0
    threshold = max(THRESHOLD_REL, THRESHOLD_ABS)

    payloads = [
        (f"1' AND SLEEP({SLEEP_SECONDS})--", "MySQL/MariaDB"),
        (f"1'; SELECT pg_sleep({SLEEP_SECONDS})--", "PostgreSQL"),
        (f"1'; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--", "MSSQL"),
    ]

    for payload, db_type in payloads:
        path = _build_path(ep, param_name, payload)
        t0 = time.perf_counter()
        r = await _safe_get(client, f"{target_url}{path}")
        elapsed = time.perf_counter() - t0
        if r is None:
            continue
        if r.status_code >= 500:
            continue
        if elapsed >= threshold:
            return {
                "level": "CRITICAL",
                "type": "SQL Injection",
                "endpoint": ep,
                "desc": f"Time-based SQLi: параметр {param_name} ({db_type}, задержка {elapsed:.1f}s, baseline {baseline_time:.1f}s)",
                "details": get_vuln_info("SQL Injection"),
            }
    return None


async def check_sqli(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]

    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1:ep.find("}")]

        finding = await _sqli_error_based(ctx.client, ctx.target_url, ep, param_name)
        if finding:
            findings.append(finding)
            continue

        finding = await _sqli_boolean_based(ctx.client, ctx.target_url, ep, param_name)
        if finding:
            findings.append(finding)
            continue

        finding = await _sqli_time_based(ctx.client, ctx.target_url, ep, param_name)
        if finding:
            findings.append(finding)

    return findings


# ================== OS Command Injection ==================
async def check_command_injection(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]
    payloads = [";id", "|id", "&whoami", "$(id)", "`id`"]
    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1:ep.find("}")]
        for payload in payloads:
            path = _build_path(ep, param_name, payload)
            r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
            if r is None:
                continue
            body = _body(r)
            if any(sig in body for sig in ["uid=", "gid=", "root:", "windows ip"]):
                findings.append({
                    "level": "CRITICAL",
                    "type": "OS Command Injection",
                    "endpoint": ep,
                    "desc": f"Возможна команда ОС через параметр {param_name}",
                    "details": get_vuln_info("OS Command Injection"),
                })
                break
    return findings


# ================== Error leak ==================
async def check_error_leak(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    """
    Проверяем до 5 param-эндпоинтов — не хочется долбить API десятками
    «мусорных» запросов. Одного 500-ответа с traceback достаточно,
    чтобы зафиксировать утечку.
    """
    findings = []
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p][:5]

    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1:ep.find("}")]
        path = _build_path(ep, param_name, "invalid'")
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None:
            continue
        body = _body(r)
        if any(k in body for k in ["traceback", "stack trace", "at line", 'file "']):
            findings.append({
                "level": "MEDIUM",
                "type": "Information Leak via Errors",
                "endpoint": ep,
                "desc": "В ответе содержатся детали ошибки (stack trace)",
                "details": get_vuln_info("Information Leak via Errors"),
            })
    return findings