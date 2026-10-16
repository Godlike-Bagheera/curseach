"""
Пакет проверок безопасности API.
Публичный API (используется в web_app.py):
    get_checks_by_mode(mode, selected)
    get_available_checks()
    CHECK_METADATA
    ALL_CHECKS
"""

from typing import Awaitable, Callable, Dict, List, Optional

# ---------- Реэкспорт проверок ----------
from .injection import check_sqli, check_command_injection, check_error_leak
from .xss import check_xss
from .access import (
    check_idor,
    check_idor_auth,
    check_csrf,
    check_cors,
    check_captcha,
)
from .auth import check_cross_user_idor, check_bfla
from .headers import (
    check_security_headers,
    check_tls_version,
    check_unsafe_methods,
)
from .data import check_sensitive_data, check_sca
from .logic import (
    check_business_logic,
    check_pagination,
    check_mass_assignment,
    check_graphql_introspection,
)
from .misc import (
    check_hidden_paths,
    check_http_only,
    check_content_type_validation,
    check_rate_limiting,
)

from .descriptions import VULN_DESCRIPTIONS, get_vuln_info
from .base import ScanContext


ALL_CHECKS: List[Callable[..., Awaitable[List[Dict]]]] = [
    check_sqli,
    check_xss,
    check_hidden_paths,
    check_idor,
    check_idor_auth,
    check_cross_user_idor,      # новое
    check_bfla,                 # новое
    check_security_headers,
    check_sensitive_data,
    check_cors,
    check_rate_limiting,
    check_command_injection,
    check_error_leak,
    check_http_only,
    check_csrf,
    check_unsafe_methods,
    check_content_type_validation,
    check_sca,
    check_captcha,
    check_business_logic,
    check_pagination,
    check_tls_version,
    check_mass_assignment,
    check_graphql_introspection,
]


CHECK_METADATA = {
    "check_sqli":                    {"name": "SQL-инъекция",               "quick": True,  "level": "CRITICAL"},
    "check_xss":                     {"name": "Отражённый XSS",             "quick": True,  "level": "MEDIUM"},
    "check_hidden_paths":            {"name": "Скрытые пути",               "quick": False, "level": "MEDIUM"},
    "check_idor":                    {"name": "Нарушение контроля доступа", "quick": True,  "level": "CRITICAL"},
    "check_idor_auth":               {"name": "IDOR: auth vs аноним",       "quick": True,  "level": "CRITICAL"},
    "check_cross_user_idor":         {"name": "Cross-user IDOR (BOLA)",     "quick": True,  "level": "CRITICAL"},
    "check_bfla":                    {"name": "BFLA (admin без роли)",      "quick": True,  "level": "CRITICAL"},
    "check_security_headers":        {"name": "Заголовки безопасности",     "quick": True,  "level": "MEDIUM"},
    "check_sensitive_data":          {"name": "Утечка данных",              "quick": True,  "level": "HIGH"},
    "check_cors":                    {"name": "Открытый CORS",              "quick": True,  "level": "MEDIUM"},
    "check_rate_limiting":           {"name": "Ограничение запросов",       "quick": False, "level": "LOW"},
    "check_command_injection":       {"name": "Инъекция команд ОС",         "quick": True,  "level": "CRITICAL"},
    "check_error_leak":              {"name": "Утечка через ошибки",        "quick": True,  "level": "MEDIUM"},
    "check_http_only":               {"name": "HTTP без HTTPS",             "quick": True,  "level": "MEDIUM"},
    "check_csrf":                    {"name": "Защита от CSRF",             "quick": False, "level": "MEDIUM"},
    "check_unsafe_methods":          {"name": "Опасные HTTP-методы",        "quick": False, "level": "MEDIUM"},
    "check_content_type_validation": {"name": "Валидация Content-Type",     "quick": False, "level": "LOW"},
    "check_sca":                     {"name": "Уязвимые зависимости",       "quick": False, "level": "CRITICAL"},
    "check_captcha":                 {"name": "Защита от брутфорса",        "quick": False, "level": "MEDIUM"},
    "check_business_logic":          {"name": "Бизнес-логика",              "quick": False, "level": "HIGH"},
    "check_pagination":              {"name": "Пагинация",                  "quick": False, "level": "LOW"},
    "check_tls_version":             {"name": "Версия TLS",                 "quick": False, "level": "MEDIUM"},
    "check_mass_assignment":         {"name": "Массовое присвоение",        "quick": False, "level": "HIGH"},
    "check_graphql_introspection":   {"name": "GraphQL-интроспекция",       "quick": False, "level": "MEDIUM"},
}


def get_checks_by_mode(mode: str, selected: Optional[List[str]] = None) -> list:
    if mode == "quick":
        return [fn for fn in ALL_CHECKS if CHECK_METADATA.get(fn.__name__, {}).get("quick")]
    if mode == "custom":
        if not selected:
            return []
        return [fn for fn in ALL_CHECKS if fn.__name__ in selected]
    return list(ALL_CHECKS)


def get_available_checks() -> List[Dict]:
    return [
        {
            "id": fn.__name__,
            "name": CHECK_METADATA.get(fn.__name__, {}).get("name", fn.__name__),
            "quick": CHECK_METADATA.get(fn.__name__, {}).get("quick", False),
            "level": CHECK_METADATA.get(fn.__name__, {}).get("level", "MEDIUM"),
        }
        for fn in ALL_CHECKS
    ]