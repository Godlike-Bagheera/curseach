"""Справочник уязвимостей: популярные карточки (EN + RU + смысл) и реестр всех проверок сканера.

Реестр строится из CHECK_METADATA (checks/__init__.py) + descriptions.py, поэтому
страница /vulns никогда не разъезжается с реальным набором проверок.

Карточки понятны новичку: уровень опасности простым языком, пример из жизни,
а коды CWE / OWASP снабжены человеческими названиями и подсказками-расшифровками.
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
    "Server-Side Request Forgery": "check_ssrf",
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
    "check_ssrf": "Server-Side Request Forgery",
}

# Русские названия типов без отдельной карточки в «популярных» — для заголовков реестра.
REGISTRY_RU: dict[str, str] = {
    "Hidden Path": "Скрытые пути",
    "Open CORS": "Открытый CORS",
    "HTTP without HTTPS": "HTTP без HTTPS",
    "Unsafe HTTP Methods": "Опасные HTTP-методы",
    "Missing Content-Type Validation": "Проверка Content-Type",
    "Dependency Manifest Exposed": "Манифест зависимостей наружу",
    "Lack of CAPTCHA": "Нет CAPTCHA",
    "Business Logic Error": "Ошибки бизнес-логики",
    "Missing Pagination": "Нет пагинации",
    "GraphQL Introspection": "GraphQL-интроспекция",
}

# Дополнительные якоря реестра: одна проверка ловит несколько типов из VULN_DESCRIPTIONS,
# и ссылки отчётов /vulns#<slug> должны попадать на её карточку.
EXTRA_ANCHORS: dict[str, list[str]] = {
    "check_security_headers": ["Missing CSP", "Missing HSTS", "Weak CSP"],
    "check_tls_version": [
        "TLS Certificate Expired",
        "TLS Certificate Expiring Soon",
        "TLS Certificate Untrusted",
    ],
    "check_sca": ["Vulnerable Dependencies (SCA)"],
}

# ---------- Уровни опасности: понятные подписи и подсказки ----------
LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
LEVEL_INFO = {
    "CRITICAL": {
        "ru": "КРИТИЧЕСКИЙ",
        "hint": (
            "Критический риск (CRITICAL): взлом возможен уже сейчас — могут украсть всю базу "
            "или захватить сервер. Исправлять немедленно."
        ),
    },
    "HIGH": {
        "ru": "ВЫСОКИЙ",
        "hint": (
            "Высокий риск (HIGH): реальная утечка данных или доступ к чужим аккаунтам. Исправлять в ближайшее время."
        ),
    },
    "MEDIUM": {
        "ru": "СРЕДНИЙ",
        "hint": (
            "Средний риск (MEDIUM): заметно повышает опасность, но для вреда обычно нужны "
            "дополнительные условия. Плановое исправление."
        ),
    },
    "LOW": {
        "ru": "НИЗКИЙ",
        "hint": "Низкий риск (LOW): мелкие недочёты и «гигиена» безопасности. Исправить при случае.",
    },
}
# Для уязвимостей без автоматической проверки уровень задаётся вручную.
GUIDE_LEVEL_FALLBACK = {"Server-Side Request Forgery": "HIGH"}

# ---------- Человеческие расшифровки кодов ----------
CWE_RU = {
    "CWE-20": "Некорректная проверка ввода",
    "CWE-78": "Инъекция команд ОС",
    "CWE-79": "Межсайтовый скриптинг (XSS)",
    "CWE-89": "SQL-инъекция",
    "CWE-200": "Раскрытие секретной информации",
    "CWE-209": "Утечка через сообщения об ошибках",
    "CWE-295": "Неверная проверка сертификата",
    "CWE-307": "Нет защиты от перебора паролей",
    "CWE-319": "Передача данных открытым текстом",
    "CWE-326": "Слабое шифрование (старый TLS)",
    "CWE-347": "Нет проверки цифровой подписи",
    "CWE-352": "Подделка запросов (CSRF)",
    "CWE-639": "Доступ по чужому номеру (IDOR)",
    "CWE-650": "Опасные HTTP-методы",
    "CWE-693": "Отключены механизмы защиты",
    "CWE-770": "Ресурсы без ограничений",
    "CWE-840": "Нарушение бизнес-правил",
    "CWE-862": "Нет проверки прав на действие",
    "CWE-915": "Массовое присваивание полей",
    "CWE-918": "Подделка запросов сервером (SSRF)",
    "CWE-942": "Слишком открытый CORS",
    "CWE-1104": "Уязвимая сторонняя библиотека",
}
OWASP_API_RU = {
    "API1": "Нарушение авторизации на уровне объекта (BOLA)",
    "API2": "Сломанная аутентификация",
    "API3": "Нарушение авторизации на уровне полей объекта (BOPLA)",
    "API4": "Расход ресурсов без лимитов",
    "API5": "Нарушение авторизации на уровне функций (BFLA)",
    "API6": "Доступ к чувствительным бизнес-процессам",
    "API7": "Подделка запросов сервером (SSRF)",
    "API8": "Небезопасная конфигурация",
    "API9": "Неучтённые («теневые») API",
    "API10": "Небезопасное использование внешних API",
}
OWASP_TOP10_RU = {
    "A01": "Сломанный контроль доступа",
    "A02": "Проблемы шифрования",
    "A03": "Инъекции",
    "A04": "Небезопасный дизайн",
    "A05": "Небезопасная конфигурация",
    "A06": "Уязвимые компоненты",
    "A07": "Сломанная аутентификация",
    "A08": "Нарушение целостности данных",
    "A09": "Пробелы в логировании",
    "A10": "Подделка запросов сервером (SSRF)",
}


def slugify(en: str) -> str:
    """Стабильный якорь карточки: 'JWT alg=none' -> 'jwt-alg-none'."""
    return re.sub(r"[^a-z0-9]+", "-", en.lower()).strip("-")


def _info(vuln_type: str) -> dict:
    return dict(get_vuln_info(vuln_type))


def _cwe_tags(codes: list[str]) -> list[dict]:
    return [
        {
            "code": c,
            "name": CWE_RU.get(c, "тип ошибки"),
            "title": f"{c} — {CWE_RU.get(c, 'тип ошибки')}. CWE: международный каталог типов ошибок безопасности (MITRE).",
        }
        for c in codes
    ]


def _api_tags(codes: list[str]) -> list[dict]:
    tags = []
    for code in codes:
        short = code.split(":")[0]
        name = OWASP_API_RU.get(short, "риск API")
        tags.append(
            {
                "code": code,
                "name": name,
                "title": f"OWASP API Security Top 10 (2023) — {short}: {name}. Рейтинг 10 главных рисков безопасности API.",
            }
        )
    return tags


def _top10_tag(code: str) -> dict | None:
    if not code:
        return None
    short = code.split(":")[0]
    name = OWASP_TOP10_RU.get(short, "риск веб-приложений")
    return {
        "code": code,
        "name": name,
        "title": f"OWASP Top 10 (2021) — {short}: {name}. Рейтинг 10 главных рисков безопасности веб-приложений.",
    }


def _related_checks(checked: str | None) -> list[str]:
    return re.findall(r"check_\w+", checked or "")


def _guide_level(en: str, check_ids: list[str]) -> str:
    levels = [CHECK_METADATA.get(cid, {}).get("level", "MEDIUM") for cid in check_ids]
    if levels:
        return max(levels, key=lambda lv: LEVEL_ORDER.get(lv, 1))
    return GUIDE_LEVEL_FALLBACK.get(en, "MEDIUM")


def _search_text(*parts: str) -> str:
    return " ".join(p for p in parts if p).lower()


def build_guide():
    """Популярные уязвимости: EN + RU + смысл + пример + уровень опасности + расшифровка кодов."""
    guide = []
    for en, ru in RU_NAMES.items():
        info = _info(en)
        checked = CHECKED_BY.get(en)
        check_ids = _related_checks(checked)
        level = _guide_level(en, check_ids)
        quick = any(CHECK_METADATA.get(cid, {}).get("quick") for cid in check_ids)
        cwe = info.get("cwe", [])
        owasp_api = info.get("owasp_api", [])
        owasp_top10 = info.get("owasp_top10", "")
        search = _search_text(
            en,
            ru,
            info.get("plain", ""),
            info.get("example", ""),
            info.get("recommendation", ""),
            checked or "",
            level,
            LEVEL_INFO[level]["ru"],
            *cwe,
            *[CWE_RU.get(c, "") for c in cwe],
            *owasp_api,
            *[OWASP_API_RU.get(o.split(":")[0], "") for o in owasp_api],
            owasp_top10,
            OWASP_TOP10_RU.get(owasp_top10.split(":")[0], ""),
        )
        guide.append(
            {
                "en": en,
                "ru": ru,
                "slug": slugify(en),
                "meaning": info.get("plain", ""),
                "example": info.get("example", ""),
                "recommendation": info.get("recommendation", ""),
                "level": level,
                "level_ru": LEVEL_INFO[level]["ru"],
                "level_hint": LEVEL_INFO[level]["hint"],
                "quick": quick,
                "cwe": cwe,
                "owasp_api": owasp_api,
                "owasp_top10": owasp_top10,
                "cwe_tags": _cwe_tags(cwe),
                "api_tags": _api_tags(owasp_api),
                "top10_tag": _top10_tag(owasp_top10),
                "checked_by": checked,
                "checks": check_ids,
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
        recommendation = info.get("recommendation", "")
        cwe = info.get("cwe", [])
        owasp_api = info.get("owasp_api", [])
        owasp_top10 = info.get("owasp_top10", "")
        level = meta.get("level", "MEDIUM")
        title_en = vt or meta.get("name", cid)
        title_ru = RU_NAMES.get(vt) or REGISTRY_RU.get(vt) or meta.get("name", cid)
        # Якоря для типов без карточки в «популярных»: ссылки отчётов /vulns#<slug> ведут сюда.
        anchors = [slugify(vt)] if vt and vt not in RU_NAMES else []
        anchors += [slugify(t) for t in EXTRA_ANCHORS.get(cid, [])]
        search = _search_text(
            cid,
            meta.get("name", ""),
            title_en,
            title_ru,
            meaning,
            recommendation,
            level,
            LEVEL_INFO.get(level, {}).get("ru", ""),
            *cwe,
            *[CWE_RU.get(c, "") for c in cwe],
            *owasp_api,
            *[OWASP_API_RU.get(o.split(":")[0], "") for o in owasp_api],
            owasp_top10,
            OWASP_TOP10_RU.get(owasp_top10.split(":")[0], ""),
        )
        registry.append(
            {
                "id": cid,
                "name": meta.get("name", cid),
                "title_en": title_en,
                "title_ru": title_ru,
                "anchors": anchors,
                "level": level,
                "level_ru": LEVEL_INFO.get(level, LEVEL_INFO["MEDIUM"])["ru"],
                "level_hint": LEVEL_INFO.get(level, LEVEL_INFO["MEDIUM"])["hint"],
                "quick": bool(meta.get("quick")),
                "vuln_type": vt,
                "meaning": meaning,
                "example": info.get("example", ""),
                "recommendation": recommendation,
                "cwe": cwe,
                "owasp_api": owasp_api,
                "owasp_top10": owasp_top10,
                "cwe_tags": _cwe_tags(cwe),
                "api_tags": _api_tags(owasp_api),
                "top10_tag": _top10_tag(owasp_top10),
                "guide_slug": slugify(vt) if vt in RU_NAMES else None,
                "search": search,
            }
        )
    return registry
