"""Контроль доступа: IDOR, cross-auth IDOR, CSRF, CORS, CAPTCHA."""

from typing import Dict, List, Optional

import httpx

from .base import (
    ScanContext,
    _safe_get,
    _safe_post,
    _safe_options,
    _content_hash,
    _body,
    _method_not_supported,
    _is_auth_endpoint,
)
from .descriptions import get_vuln_info


# ================== IDOR / Broken Access Control ==================
async def check_idor(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    seen_endpoints = set()

    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]
    for ep in param_endpoints:
        param_name = ep[ep.find("{") + 1:ep.find("}")]
        responses: Dict[str, httpx.Response] = {}
        for test_id in ["1", "2", "3", "0", "-1", "100"]:
            path = ep.replace(f"{{{param_name}}}", test_id)
            r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
            if r is None:
                continue
            if r.status_code == 200:
                responses[test_id] = r

        if len(responses) < 2:
            continue

        hashes = {tid: _content_hash(r) for tid, r in responses.items()}
        if len(set(hashes.values())) >= 2:
            ids_list = ", ".join(responses.keys())
            findings.append({
                "level": "HIGH",
                "type": "Broken Access Control",
                "endpoint": ep,
                "desc": f"Эвристика: эндпоинт возвращает данные для разных ID ({ids_list}) без проверки прав",
                "details": get_vuln_info("Broken Access Control"),
            })
            seen_endpoints.add(ep)

    sensitive_keywords = ["keys", "admin", "system", "config", "settings", "internal", "debug"]
    for ep in endpoints:
        if ep in seen_endpoints:
            continue
        if not any(k in ep for k in sensitive_keywords):
            continue
        if "{" in ep:
            continue
        r = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        if r is None:
            continue
        if r.status_code == 200:
            findings.append({
                "level": "CRITICAL",
                "type": "Broken Access Control",
                "endpoint": ep,
                "desc": "Чувствительный эндпоинт доступен без аутентификации",
                "details": get_vuln_info("Broken Access Control"),
            })

    return findings


# ================== Cross-auth IDOR ==================
async def check_idor_auth(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    """
    Сравнивает ответы с авторизацией и без.
    Если для статического эндпоинта они идентичны (200/200 и одинаковый контент) —
    значит сервер НЕ проверяет токен, и эндпоинт реально публичный.
    Работает только когда скан запущен с auth.
    """
    if not ctx.has_auth:
        return []

    findings = []
    for ep in endpoints:
        if "{" in ep or "}" in ep:
            continue

        r_auth = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        r_anon = await _safe_get(ctx.anon_client, f"{ctx.target_url}{ep}")
        if r_auth is None or r_anon is None:
            continue

        if r_auth.status_code != 200 or r_anon.status_code != 200:
            continue

        if _content_hash(r_auth) == _content_hash(r_anon):
            findings.append({
                "level": "CRITICAL",
                "type": "Broken Access Control",
                "endpoint": ep,
                "desc": "Эндпоинт возвращает идентичный ответ с токеном и без него — авторизация не проверяется",
                "details": get_vuln_info("Broken Access Control"),
            })
    return findings


# ================== CSRF (эвристика) ==================
async def check_csrf(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []

    # Логин / регистрация — не state-changing эндпоинты.
    # На них CSRF-токен не нужен, поэтому не проверяем их и не
    # считаем отсутствие токена уязвимостью.
    post_endpoints = [
        e for e in endpoints
        if "{" not in e and "}" not in e
        and e.startswith("/")
        and not _is_auth_endpoint(e)
    ]
    if not post_endpoints:
        return findings

    test_path = post_endpoints[0]
    r = await _safe_post(ctx.client, f"{ctx.target_url}{test_path}", json={})
    if _method_not_supported(r):
        return findings
    if r is None:
        return findings

    # Если сервер не обработал запрос (401/403/422/400) — мы не можем
    # судить о наличии CSRF-защиты: нечего защищать, действие не выполнено.
    if not (200 <= r.status_code < 300):
        return findings

    has_csrf_header = "x-csrf-token" in r.headers
    set_cookie = r.headers.get("set-cookie", "")
    has_csrf_cookie = "csrf" in set_cookie.lower()

    if not has_csrf_header and not has_csrf_cookie:
        findings.append({
            "level": "MEDIUM",
            "type": "Missing CSRF Protection",
            "endpoint": test_path,
            "desc": "Эвристика: не обнаружен CSRF-токен",
            "details": get_vuln_info("Missing CSRF Protection"),
        })
    return findings


# ================== CORS ==================
async def check_cors(
    ctx: ScanContext, endpoints: Optional[List[str]] = None
) -> List[Dict]:
    findings = []
    r = await _safe_options(ctx.client, ctx.target_url)
    if r is None:
        r = await _safe_get(ctx.client, ctx.target_url)
    if r is None:
        return findings
    acao = r.headers.get("access-control-allow-origin", "")
    if acao.strip() == "*":
        findings.append({
            "level": "MEDIUM",
            "type": "Open CORS",
            "endpoint": "/",
            "desc": "CORS разрешает любые источники",
            "details": get_vuln_info("Open CORS"),
        })
    return findings


# ================== CAPTCHA (эвристика) ==================
async def check_captcha(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    login_endpoints = [e for e in endpoints if "login" in e.lower() or "auth" in e.lower()]
    if not login_endpoints:
        return findings

    test_path = login_endpoints[0]
    got_protection = False
    got_valid_response = False
    NUM_ATTEMPTS = 10

    for _ in range(NUM_ATTEMPTS):
        r = await _safe_post(
            ctx.client, f"{ctx.target_url}{test_path}",
            json={"username": "wrong", "password": "wrong"},
        )
        if _method_not_supported(r):
            return findings
        if r is None:
            continue
        got_valid_response = True
        if r.status_code == 429 or "captcha" in _body(r):
            got_protection = True
            break

    if got_valid_response and not got_protection:
        findings.append({
            "level": "MEDIUM",
            "type": "Lack of CAPTCHA",
            "endpoint": test_path,
            "desc": f"Эвристика: {NUM_ATTEMPTS} неудачных попыток логина не привели к блокировке",
            "details": get_vuln_info("Lack of CAPTCHA"),
        })
    return findings