"""Контроль доступа: IDOR, cross-auth IDOR, CSRF, CORS, CAPTCHA."""

from urllib.parse import urlparse

import httpx

from .base import (
    _PUBLIC_PATHS,
    ScanContext,
    _body,
    _content_hash,
    _endpoint_explicitly_public,
    _endpoint_requires_security,
    _is_auth_endpoint,
    _is_spa_shell,
    _method_not_supported,
    _norm_body,
    _norm_hash,
    _safe_get,
    _safe_options,
    _safe_post,
    _writable_endpoints,
)
from .descriptions import get_vuln_info

_IDOR_OWNERSHIP_FIELDS = (
    "user_id",
    "owner_id",
    "account_id",
    "tenant_id",
    "customer_id",
    "userid",
    "owner",
    "email",
    "username",
)
_IDOR_SENSITIVE_PATHS = (
    "order",
    "user",
    "account",
    "profile",
    "report",
    "invoice",
    "customer",
    "cart",
    "address",
    "payment",
    "private",
    "keys",
    "admin",
    "system",
    "config",
    "settings",
    "internal",
    "debug",
    "wallet",
    "transaction",
)


def _idor_ownership_signal(ep: str, body: str) -> bool:
    low = (body or "").lower()
    if any(f in low for f in _IDOR_OWNERSHIP_FIELDS):
        return True
    epl = (ep or "").lower()
    return any(k in epl for k in _IDOR_SENSITIVE_PATHS)


# ================== IDOR / Broken Access Control ==================
async def check_idor(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    seen_endpoints = set()

    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]
    for ep in param_endpoints:
        if ep in _PUBLIC_PATHS or _endpoint_explicitly_public(ctx, ep):
            continue
        param_name = ep[ep.find("{") + 1 : ep.find("}")]
        responses: dict[str, httpx.Response] = {}
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
            sample_body = _body(next(iter(responses.values())))
            if not _idor_ownership_signal(ep, sample_body):
                continue
            ids_list = ", ".join(responses.keys())
            findings.append(
                {
                    "level": "HIGH",
                    "type": "Broken Access Control",
                    "endpoint": ep,
                    "desc": f"Эвристика: эндпоинт возвращает данные для разных ID ({ids_list}) без проверки прав",
                    "details": get_vuln_info("Broken Access Control"),
                }
            )
            seen_endpoints.add(ep)

    sensitive_keywords = ["keys", "admin", "system", "config", "settings", "internal", "debug"]
    base = await _safe_get(ctx.client, f"{ctx.target_url}/__nonexistent_baseline_idor__")
    base_status = base.status_code if base is not None else None
    base_body = _norm_body(base) if base is not None else None
    for ep in endpoints:
        if ep in seen_endpoints:
            continue
        if not any(k in ep for k in sensitive_keywords):
            continue
        if "{" in ep or _is_auth_endpoint(ep):
            continue
        r = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        if r is None:
            continue
        if r.status_code == 200:
            if base_body is not None and r.status_code == base_status and _norm_body(r) == base_body:
                continue
            if _is_spa_shell(r.text or ""):
                continue
            findings.append(
                {
                    "level": "CRITICAL",
                    "type": "Broken Access Control",
                    "endpoint": ep,
                    "desc": "Чувствительный эндпоинт доступен без аутентификации",
                    "details": get_vuln_info("Broken Access Control"),
                }
            )

    return findings


# ================== Cross-auth IDOR ==================
async def check_idor_auth(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    if not ctx.has_auth:
        return []

    findings: list = []
    for ep in endpoints:
        if "{" in ep or "}" in ep:
            continue
        if ep in _PUBLIC_PATHS or _is_auth_endpoint(ep):
            continue
        if _endpoint_explicitly_public(ctx, ep):
            continue

        r_auth = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        r_anon = await _safe_get(ctx.anon_client, f"{ctx.target_url}{ep}")
        if r_auth is None or r_anon is None:
            continue

        if r_auth.status_code != 200 or r_anon.status_code != 200:
            continue

        if _is_spa_shell(r_auth.text or ""):
            continue
        if _norm_hash(r_auth) == _norm_hash(r_anon):
            if _endpoint_requires_security(ctx, ep):
                level = "CRITICAL"
                desc = "Эндпоинт требует авторизацию по спеке, но отдаёт идентичный ответ с токеном и без него"
            else:
                if not _idor_ownership_signal(ep, _body(r_auth)):
                    continue
                level = "MEDIUM"
                desc = (
                    "Эвристика: идентичный ответ с токеном и без него — возможно, эндпоинт публичный; проверьте вручную"
                )
            findings.append(
                {
                    "level": level,
                    "type": "Broken Access Control",
                    "endpoint": ep,
                    "desc": desc,
                    "details": get_vuln_info("Broken Access Control"),
                }
            )
    return findings


# ================== CSRF (эвристика) ==================
async def check_csrf(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """Перебираем ВСЕ writable-эндпоинты, не только первый 2xx.

    Раньше проверялся только первый writable-эндпоинт, и если он легитимно
    без CSRF (публичный API), то до остальных проверка не доходила.
    Теперь проходим по всем и собираем находки на каждый уязвимый.
    """
    findings: list = []
    post_endpoints = _writable_endpoints(ctx, endpoints)
    if not post_endpoints:
        return findings

    auth_header = (ctx.client.headers.get("authorization") or "").lower()
    bearer_no_cookies = auth_header.startswith("bearer ") and len(ctx.client.cookies) == 0

    for test_path in post_endpoints:
        r = await _safe_post(ctx.client, f"{ctx.target_url}{test_path}", json={})
        if r is None or _method_not_supported(r):
            continue
        if not (200 <= r.status_code < 300):
            continue
        set_cookie = r.headers.get("set-cookie", "")
        if bearer_no_cookies and not set_cookie:
            continue
        has_csrf_header = "x-csrf-token" in r.headers
        has_csrf_cookie = "csrf" in set_cookie.lower()
        if not has_csrf_header and not has_csrf_cookie:
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": "Missing CSRF Protection",
                    "endpoint": test_path,
                    "desc": "Эвристика: не обнаружен CSRF-токен",
                    "details": get_vuln_info("Missing CSRF Protection"),
                }
            )
    return findings


# ================== CORS ==================
async def check_cors(ctx: ScanContext, endpoints: list[str] | None = None) -> list[dict]:
    """Проверяем CORS на корне и на первых 5 документированных эндпоинтах.

    Preflight (OPTIONS с Origin + Access-Control-Request-Method) — самое
    надёжное; при 405/501 падаем на GET с Origin.
    """
    findings: list = []
    urls_to_test: list[str] = [ctx.target_url]
    for ep in (endpoints or []):
        if len(urls_to_test) >= 5:
            break
        if "{" in ep or "}" in ep:
            continue
        urls_to_test.append(f"{ctx.target_url}{ep}")

    for test_url in urls_to_test:
        r = await _safe_options(
            ctx.client,
            test_url,
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        if r is None or _method_not_supported(r):
            r = await _safe_get(ctx.client, test_url, headers={"Origin": "https://evil.example"})
        if r is None:
            continue

        acao = r.headers.get("access-control-allow-origin", "").strip()
        creds = r.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        ep_path = urlparse(test_url).path or "/"

        if acao == "https://evil.example" and creds:
            findings.append(
                {
                    "level": "HIGH",
                    "type": "Open CORS",
                    "endpoint": ep_path,
                    "desc": "CORS отражает произвольный Origin с Allow-Credentials: true — чтение ответов с cookies из любого сайта",
                    "details": get_vuln_info("Open CORS"),
                }
            )
            return findings

        if acao == "*":
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": "Open CORS",
                    "endpoint": ep_path,
                    "desc": "CORS разрешает любые источники (Access-Control-Allow-Origin: *)",
                    "details": get_vuln_info("Open CORS"),
                }
            )
            return findings

    return findings


# ================== CAPTCHA (эвристика) ==================
async def check_captcha(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    login_endpoints = [e for e in endpoints if "login" in e.lower() or "auth" in e.lower()]
    if not login_endpoints:
        return findings

    test_path = login_endpoints[0]
    got_protection = False
    got_valid_response = False
    NUM_ATTEMPTS = 10

    for _ in range(NUM_ATTEMPTS):
        r = await _safe_post(
            ctx.client,
            f"{ctx.target_url}{test_path}",
            json={"username": "wrong", "password": "wrong"},
        )
        if _method_not_supported(r):
            return findings
        if r is None:
            continue
        if r.status_code == 429 or "captcha" in _body(r):
            got_protection = True
            break
        if r.status_code in (400, 401, 422):
            got_valid_response = True

    if got_valid_response and not got_protection:
        findings.append(
            {
                "level": "MEDIUM",
                "type": "Lack of CAPTCHA",
                "endpoint": test_path,
                "desc": f"Эвристика: {NUM_ATTEMPTS} неудачных попыток логина не привели к блокировке",
                "details": get_vuln_info("Lack of CAPTCHA"),
            }
        )
    return findings
