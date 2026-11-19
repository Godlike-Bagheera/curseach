"""Справочник уязвимостей: популярные карточки (EN + RU + смысл) и реестр всех проверок сканера.

Реестр строится из CHECK_METADATA (checks/__init__.py) + descriptions.py, поэтому
страница /vulns никогда не разъезжается с реальным набором проверок.
"""

import re

from checks import CHECK_METADATA
from checks.descriptions import get_vuln_info

RU_NAMES = {
    "SQL Injection": "SQL-инъекция",
    "Reflected XSS": "Межсайтовый скриптинг (отражённый XSS)",
    "Broken Access Control": "Нарушение контроля доступа (IDOR / BOLA)",
    "Broken Function Level Authorization": "Доступ к чужим функциям (BFLA)",
    "JWT alg=none": "Подделка JWT без подписи (сломанная аутентификация)",
    "Sensitive Data Exposure": "Утечка чувствительных данных",
    "Missing Security Headers": "Отсутствие заголовков безопасности",
    "Missing CSRF Protection": "Межсайтовая подделка запроса (CSRF)",
    "OS Command Injection": "Инъекция команд операционной системы",
    "Information Leak via Errors": "Утечка информации через сообщения об ошибках",
    "Weak TLS Version": "Слабый TLS и проблемы сертификата",
    "Vulnerable Dependency (OSV)": "Уязвимые зависимости (устаревшие библиотеки)",
    "Mass Assignment": "Массовое присваивание полей",
    "Lack of Rate Limiting": "Отсутствие ограничения частоты запросов",
    "Server-Side Request Forgery": "Подделка запросов со стороны сервера (SSRF)",
}
CHECKED_BY = {
    "SQL Injection": "check_sqli",
    "Reflected XSS": "check_xss",
    "Broken Access Control": "check_idor / check_idor_auth / check_cross_user_idor",
    "Broken Function Level Authorization": "check_bfla",
    "JWT alg=none": "check_jwt_none",
    "Sensitive Data Exposure": "check_sensitive_data",
    "Missing Security Headers": "check_security_headers",
    "Missing CSRF Protection": "check_csrf",
    "OS Command Injection": "check_command_injection",
    "Information Leak via Errors": "check_error_leak",
    "Weak TLS Version": "check_tls_version",
    "Vulnerable Dependency (OSV)": "check_osv_sca",
    "Mass Assignment": "check_mass_assignment",
    "Lack of Rate Limiting": "check_rate_limiting",
    "Server-Side Request Forgery": None,
}
EXTRA = {
    "Broken Function Level Authorization": {
        "plain": "Обычный пользователь вызывает функции, доступные только другой роли "
        "(например, админские эндпоинты): сервер проверяет «кто вошёл», но не "
        "«кому можно это действие».",
        "recommendation": "Проверяй роль/права на каждом эндпоинте, а не только факт "
        "аутентификации; deny-by-default для привилегированных операций.",
        "cwe": ["CWE-862"],
        "owasp_api": ["API5:2023"],
        "owasp_top10": "A01:2021",
    },
    "Server-Side Request Forgery": {
        "plain": "Сервер сам ходит по URL, который подсунул атакующий: так можно достучаться "
        "до внутренних сервисов и облачных metadata-эндпоинтов, украсть токены или "
        "просканировать сеть изнутри.",
        "recommendation": "Валидируй схему/хост/порт, запрещай private и link-local диапазоны, "
        "пинни проверенный IP (защита от DNS-rebinding), отключи редиректы.",
        "cwe": ["CWE-918"],
        "owasp_api": [],
        "owasp_top10": "A10:2021",
    },
}
CHECK_VULN = {
    "check_sqli": "SQL Injection",
    "check_xss": "Reflected XSS",
    "check_hidden_paths": "Hidden Path",
    "check_idor": "Broken Access Control",
    "check_idor_auth": "Broken Access Control",
    "check_cross_user_idor": "Broken Access Control",
    "check_bfla": "Broken Function Level Authorization",
    "check_jwt_none": "JWT alg=none",
    "check_security_headers": "Missing Security Headers",
    "check_sensitive_data": "Sensitive Data Exposure",
    "check_cors": "Open CORS",
    "check_rate_limiting": "Lack of Rate Limiting",
    "check_command_injection": "OS Command Injection",
    "check_error_leak": "Information Leak via Errors",
    "check_http_only": "HTTP without HTTPS",
    "check_csrf": "Missing CSRF Protection",
    "check_unsafe_methods": "Unsafe HTTP Methods",
    "check_content_type_validation": "Missing Content-Type Validation",
    "check_sca": "Dependency Manifest Exposed",
    "check_captcha": "Lack of CAPTCHA",
    "check_business_logic": "Business Logic Error",
    "check_pagination": "Missing Pagination",
    "check_tls_version": "Weak TLS Version",
    "check_mass_assignment": "Mass Assignment",
    "check_graphql_introspection": "GraphQL Introspection",
    "check_osv_sca": "Vulnerable Dependency (OSV)",
}


def slugify(en: str) -> str:
    """Стабильный якорь карточки: 'JWT alg=none' -> 'jwt-alg-none'."""
    return re.sub(r"[^a-z0-9]+", "-", en.lower()).strip("-")


def _info(vuln_type: str) -> dict:
    return dict(EXTRA.get(vuln_type) or get_vuln_info(vuln_type))


def build_guide():
    """Популярные уязвимости: EN + RU-название + RU-смысл + классификация."""
    guide = []
    for en, ru in RU_NAMES.items():
        info = _info(en)
        checked = CHECKED_BY.get(en)
        search = " ".join(
            [
                en,
                ru,
                info.get("plain", ""),
                info.get("recommendation", ""),
                checked or "",
                *info.get("cwe", []),
                *info.get("owasp_api", []),
                info.get("owasp_top10", ""),
            ]
        ).lower()
        guide.append(
            {
                "en": en,
                "ru": ru,
                "slug": slugify(en),
                "meaning": info.get("plain", ""),
                "recommendation": info.get("recommendation", ""),
                "cwe": info.get("cwe", []),
                "owasp_api": info.get("owasp_api", []),
                "owasp_top10": info.get("owasp_top10", ""),
                "checked_by": checked,
                "search": search,
            }
        )
    return guide


def build_registry():
    """Все проверки сканера — напрямую из CHECK_METADATA, без ручного дублирования."""
    registry = []
    for cid, meta in CHECK_METADATA.items():
        vt = CHECK_VULN.get(cid, "")
        info = _info(vt) if vt else {}
        meaning = info.get("plain", "")
        cwe = info.get("cwe", [])
        owasp_api = info.get("owasp_api", [])
        owasp_top10 = info.get("owasp_top10", "")
        search = " ".join([cid, meta.get("name", ""), vt, meaning, *cwe, *owasp_api, owasp_top10]).lower()
        registry.append(
            {
                "id": cid,
                "name": meta.get("name", cid),
                "level": meta.get("level", "MEDIUM"),
                "quick": bool(meta.get("quick")),
                "vuln_type": vt,
                "meaning": meaning,
                "recommendation": info.get("recommendation", ""),
                "cwe": cwe,
                "owasp_api": owasp_api,
                "owasp_top10": owasp_top10,
                "guide_slug": slugify(vt) if vt in RU_NAMES else None,
                "search": search,
            }
        )
    return registry
