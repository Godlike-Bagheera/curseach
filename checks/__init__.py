"""
Пакет проверок безопасности API.
Публичный API (используется в web_app.py):
    get_checks_by_mode(mode, selected)
    get_available_checks()
    CHECK_METADATA
    ALL_CHECKS
"""

from collections.abc import Awaitable, Callable
from typing import Optional

from .access import (
    check_captcha,
    check_cors,
    check_csrf,
    check_idor,
    check_idor_auth,
)
from .auth import check_bfla, check_cross_user_idor, check_jwt_exp, check_jwt_none, check_jwt_weak_secret
from .base import (
    _EVIDENCE_LOG,
    _SCAN_CTX,
    RateLimiter,
    RequestBudget,
    ScanCancelled,
    ScanContext,
    dedup_findings,
    enrich_findings,
    ev,
)
from .cookies import check_cookie_flags
from .data import check_osv_sca, check_sca, check_sensitive_data
from .descriptions import VULN_DESCRIPTIONS, get_vuln_info
from .headers import (
    check_security_headers,
    check_tls_version,
    check_unsafe_methods,
)

# ---------- Реэкспорт проверок ----------
from .injection import check_command_injection, check_error_leak, check_sqli
from .logic import (
    check_business_logic,
    check_graphql_introspection,
    check_mass_assignment,
    check_pagination,
)
from .misc import (
    check_content_type_validation,
    check_hidden_paths,
    check_http_only,
    check_rate_limiting,
    check_security_txt,
)
from .ssrf import check_ssrf
from .surface import Surface, build_surfaces, sample_from_schema
from .traversal import check_open_redirect, check_path_traversal
from .xss import check_stored_xss, check_xss

ALL_CHECKS: list[Callable[..., Awaitable[list[dict]]]] = [
    check_sqli,
    check_xss,
    check_hidden_paths,
    check_idor,
    check_idor_auth,
    check_cross_user_idor,  # новое
    check_bfla,  # новое
    check_jwt_none,  # новое: JWT alg=none / подделка токена
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
    check_osv_sca,
    check_ssrf,
    check_path_traversal,
    check_open_redirect,
    check_cookie_flags,
    check_stored_xss,
    check_jwt_exp,
    check_security_txt,
    check_jwt_weak_secret,
]


CHECK_METADATA = {
    "check_sqli": {"name": "SQL-инъекция", "quick": True, "level": "CRITICAL"},
    "check_xss": {"name": "Отражённый XSS", "quick": True, "level": "MEDIUM"},
    "check_hidden_paths": {"name": "Скрытые пути", "quick": False, "level": "MEDIUM"},
    "check_idor": {"name": "Нарушение контроля доступа", "quick": True, "level": "CRITICAL"},
    "check_idor_auth": {"name": "IDOR: auth vs аноним", "quick": True, "level": "CRITICAL"},
    "check_cross_user_idor": {"name": "Cross-user IDOR (BOLA)", "quick": True, "level": "CRITICAL"},
    "check_bfla": {"name": "BFLA (admin без роли)", "quick": True, "level": "CRITICAL"},
    "check_jwt_none": {"name": "JWT alg=none / подделка", "quick": True, "level": "CRITICAL"},
    "check_security_headers": {"name": "Заголовки безопасности", "quick": True, "level": "MEDIUM"},
    "check_sensitive_data": {"name": "Утечка данных", "quick": True, "level": "HIGH"},
    "check_cors": {"name": "Открытый CORS", "quick": True, "level": "MEDIUM"},
    "check_rate_limiting": {"name": "Ограничение запросов", "quick": False, "level": "LOW"},
    "check_command_injection": {"name": "Инъекция команд ОС", "quick": True, "level": "CRITICAL"},
    "check_error_leak": {"name": "Утечка через ошибки", "quick": True, "level": "MEDIUM"},
    "check_http_only": {"name": "HTTP без HTTPS", "quick": True, "level": "MEDIUM"},
    "check_csrf": {"name": "Защита от CSRF", "quick": False, "level": "MEDIUM"},
    "check_unsafe_methods": {"name": "Опасные HTTP-методы", "quick": False, "level": "MEDIUM"},
    "check_content_type_validation": {"name": "Валидация Content-Type", "quick": False, "level": "LOW"},
    "check_sca": {"name": "Утечка манифеста зависимостей", "quick": False, "level": "MEDIUM"},
    "check_captcha": {"name": "Защита от брутфорса", "quick": False, "level": "MEDIUM"},
    "check_business_logic": {"name": "Бизнес-логика", "quick": False, "level": "HIGH"},
    "check_pagination": {"name": "Пагинация", "quick": False, "level": "LOW"},
    "check_tls_version": {"name": "TLS и сертификат", "quick": False, "level": "HIGH"},
    "check_mass_assignment": {"name": "Массовое присвоение", "quick": False, "level": "HIGH"},
    "check_graphql_introspection": {"name": "GraphQL-интроспекция", "quick": False, "level": "MEDIUM"},
    "check_osv_sca": {"name": "SCA: уязвимые зависимости (OSV)", "quick": False, "level": "CRITICAL"},
    "check_ssrf": {"name": "SSRF (запросы от имени сервера)", "quick": False, "level": "HIGH"},
    "check_path_traversal": {"name": "Path Traversal / LFI", "quick": True, "level": "HIGH"},
    "check_open_redirect": {"name": "Открытый редирект", "quick": True, "level": "MEDIUM"},
    "check_cookie_flags": {"name": "Флаги cookie", "quick": True, "level": "MEDIUM"},
    "check_stored_xss": {"name": "Хранимый XSS", "quick": False, "level": "HIGH"},
    "check_jwt_exp": {"name": "JWT: срок действия", "quick": True, "level": "HIGH"},
    "check_security_txt": {"name": "security.txt", "quick": False, "level": "LOW"},
    "check_jwt_weak_secret": {"name": "JWT: слабый секрет", "quick": True, "level": "CRITICAL"},
}


def get_checks_by_mode(mode: str, selected: list[str] | None = None) -> list:
    if mode == "quick":
        return [fn for fn in ALL_CHECKS if CHECK_METADATA.get(fn.__name__, {}).get("quick")]
    if mode == "custom":
        if not selected:
            return []
        return [fn for fn in ALL_CHECKS if fn.__name__ in selected]
    return list(ALL_CHECKS)


def get_available_checks() -> list[dict]:
    return [
        {
            "id": fn.__name__,
            "name": CHECK_METADATA.get(fn.__name__, {}).get("name", fn.__name__),
            "quick": CHECK_METADATA.get(fn.__name__, {}).get("quick", False),
            "level": CHECK_METADATA.get(fn.__name__, {}).get("level", "MEDIUM"),
        }
        for fn in ALL_CHECKS
    ]
