"""Справочник популярных уязвимостей: EN-название, RU-перевод, RU-смысл."""
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
    "SQL Injection": "check_sqli", "Reflected XSS": "check_xss",
    "Broken Access Control": "check_idor / check_idor_auth / check_cross_user_idor",
    "Broken Function Level Authorization": "check_bfla", "JWT alg=none": "check_jwt_none",
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
        "cwe": ["CWE-862"], "owasp_api": ["API5:2023"], "owasp_top10": "A01:2021"},
    "Server-Side Request Forgery": {
        "plain": "Сервер сам ходит по URL, который подсунул атакующий: так можно достучаться "
                 "до внутренних сервисов и облачных metadata-эндпоинтов, украсть токены или "
                 "просканировать сеть изнутри.",
        "recommendation": "Валидируй схему/хост/порт, запрещай private и link-local диапазоны, "
                          "пинни проверенный IP (защита от DNS-rebinding), отключи редиректы.",
        "cwe": ["CWE-918"], "owasp_api": [], "owasp_top10": "A10:2021"},
}


def build_guide():
    guide = []
    for en, ru in RU_NAMES.items():
        info = dict(EXTRA.get(en) or get_vuln_info(en))
        guide.append({
            "en": en, "ru": ru,
            "meaning": info.get("plain", ""),
            "recommendation": info.get("recommendation", ""),
            "cwe": info.get("cwe", []),
            "owasp_api": info.get("owasp_api", []),
            "owasp_top10": info.get("owasp_top10", ""),
            "checked_by": CHECKED_BY.get(en),
        })
    return guide
