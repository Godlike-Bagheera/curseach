"""Текстовые описания уязвимостей и рекомендации по устранению."""

from typing import Dict


VULN_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "SQL Injection": {
        "plain": "Злоумышленник может выполнить свои SQL-команды в базе данных, чтобы украсть, изменить или удалить данные.",
        "recommendation": "Используйте параметризованные запросы или ORM. Не вставляйте пользовательский ввод напрямую в SQL-строки."
    },
    "Reflected XSS": {
        "plain": "Злоумышленник может внедрить вредоносный скрипт, который выполнится в браузере пользователя.",
        "recommendation": "Экранируйте вывод, используйте CSP, не доверяйте пользовательским данным."
    },
    "Hidden Path": {
        "plain": "Найден скрытый адрес на сервере, который не должен быть публичным.",
        "recommendation": "Удалите или защитите аутентификацией все непубличные эндпоинты."
    },
    "Broken Access Control": {
        "plain": "Эндпоинт возвращает данные без проверки прав доступа.",
        "recommendation": "Внедрите контроль доступа на уровне сервера для каждого запроса."
    },
    "Missing Security Headers": {
        "plain": "В ответе сервера отсутствуют важные заголовки, защищающие от атак.",
        "recommendation": "Добавьте X-Frame-Options, X-Content-Type-Options, CSP, HSTS. X-XSS-Protection устарел — ставьте 0 или не добавляйте."
    },
    "Missing CSP": {
        "plain": "Отсутствует Content-Security-Policy, снижающий риск XSS.",
        "recommendation": "Установите CSP с ограничениями на источники скриптов."
    },
    "Missing HSTS": {
        "plain": "Отсутствует Strict-Transport-Security, заставляющий браузер использовать HTTPS.",
        "recommendation": "Добавьте HSTS-заголовок с разумным сроком действия."
    },
    "Sensitive Data Exposure": {
        "plain": "В ответе сервера видны пароли, ключи или другие секретные данные.",
        "recommendation": "Не возвращайте чувствительные данные в ответах."
    },
    "Open CORS": {
        "plain": "Сервер разрешает запросы с любых сайтов.",
        "recommendation": "Ограничьте допустимые источники конкретными доменами."
    },
    "Lack of Rate Limiting": {
        "plain": "Сервер не ограничивает количество запросов.",
        "recommendation": "Внедрите механизм ограничения запросов."
    },
    "OS Command Injection": {
        "plain": "Злоумышленник может выполнять системные команды на сервере.",
        "recommendation": "Не передавайте пользовательский ввод в системные команды."
    },
    "Information Leak via Errors": {
        "plain": "При ошибке сервер выдаёт подробные сообщения (стек-трейс).",
        "recommendation": "Используйте общие сообщения об ошибках в продакшене."
    },
    "HTTP without HTTPS": {
        "plain": "API использует HTTP, а не HTTPS. Все данные передаются открыто.",
        "recommendation": "Настройте перенаправление с HTTP на HTTPS, используйте HSTS."
    },
    "Missing CSRF Protection": {
        "plain": "Сервер не требует специальный токен для защиты от подделки запросов.",
        "recommendation": "Внедрите CSRF-токены и проверяйте их на сервере."
    },
    "Unsafe HTTP Methods": {
        "plain": "Сервер разрешает опасные методы (PUT, DELETE, TRACE).",
        "recommendation": "Отключите неиспользуемые методы или защитите их аутентификацией."
    },
    "Missing Content-Type Validation": {
        "plain": "Сервер принимает данные с неправильным Content-Type.",
        "recommendation": "Валидируйте Content-Type и отклоняйте неподдерживаемые форматы."
    },
    "Vulnerable Dependencies (SCA)": {
        "plain": "В проекте могут использоваться устаревшие библиотеки с известными уязвимостями.",
        "recommendation": "Регулярно обновляйте зависимости и используйте SCA-инструменты."
    },
    "Lack of CAPTCHA": {
        "plain": "На странице входа нет капчи, что позволяет подбирать пароли.",
        "recommendation": "Внедрите CAPTCHA или временную блокировку."
    },
    "Business Logic Error": {
        "plain": "Приложение позволяет вводить некорректные данные.",
        "recommendation": "Проверяйте входные данные на соответствие бизнес-правилам."
    },
    "Missing Pagination": {
        "plain": "Сервер может вернуть все данные сразу при большом запросе.",
        "recommendation": "Внедрите пагинацию и ограничьте максимальный размер ответа."
    },
    "Weak TLS Version": {
        "plain": "Сервер согласовал устаревшую версию TLS (1.0/1.1) — такие соединения уязвимы к расшифровке.",
        "recommendation": "Отключите TLS 1.0 и 1.1, используйте только 1.2+."
    },
    "Mass Assignment": {
        "plain": "Сервер принимает все поля, включая защищённые.",
        "recommendation": "Используйте DTO с явным списком разрешённых полей."
    },
    "GraphQL Introspection": {
        "plain": "GraphQL API позволяет получить полную схему.",
        "recommendation": "Отключите интроспекцию в продакшене."
    },
    "Dependency Manifest Exposed": {
        "plain": "Файл зависимостей доступен извне и раскрывает стек и версии библиотек — это помогает атакующему подобрать эксплойты.",
        "recommendation": "Уберите манифесты из веб-рута. Для настоящего SCA сверяйте версии с базами уязвимостей (OSV.dev, GitHub Advisory)."
    },
    "TLS Certificate Expired": {
        "plain": "Срок действия TLS-сертификата истёк — клиенты будут отклонять соединение.",
        "recommendation": "Перевыпустите сертификат (например, Let's Encrypt) и настройте автопродление."
    },
    "TLS Certificate Expiring Soon": {
        "plain": "TLS-сертификат скоро истекает — есть риск простоя HTTPS.",
        "recommendation": "Настройте автопродление и мониторинг срока действия."
    },
    "TLS Certificate Untrusted": {
        "plain": "Сертификат не проходит валидацию: самоподписанный, на другой хост или с битой цепочкой.",
        "recommendation": "Используйте сертификат доверенного CA на корректное имя и отдавайте полную цепочку."
    },
    "Vulnerable Dependency (OSV)": {
        "plain": "В манифесте зависимостей найдена библиотека с известной уязвимостью (по базе OSV.dev: CVE/GHSA). Атакующий может использовать публичный эксплойт.",
        "recommendation": "Обновите зависимость до исправленной версии (fixed versions из OSV), настройте Dependabot/renovate и регулярный SCA в CI."
    },
    "JWT alg=none": {
        "plain": (
            "Сервер принимает JWT-токены с алгоритмом 'none', то есть вообще без подписи. "
            "Злоумышленник может сам собрать токен от имени любого пользователя или админа."
        ),
        "recommendation": (
            "Явно указывайте разрешённые алгоритмы (например, только HS256/RS256), "
            "всегда проверяйте подпись и отклоняйте alg=none. Используйте актуальные библиотеки JWT."
        )
    },
}


# Классификация: CWE + OWASP API Security Top 10 (2023) + OWASP Top 10 (2021)
# и confidence по умолчанию для эвристик vs сигнатурных проверок.
VULN_META: Dict[str, Dict] = {
    "SQL Injection":                    {"cwe": ["CWE-89"],  "owasp_api": ["API8:2023"], "owasp_top10": "A03:2021", "confidence": "high"},
    "OS Command Injection":             {"cwe": ["CWE-78"],  "owasp_api": ["API8:2023"], "owasp_top10": "A03:2021", "confidence": "high"},
    "Reflected XSS":                    {"cwe": ["CWE-79"],  "owasp_api": ["API8:2023"], "owasp_top10": "A03:2021", "confidence": "high"},
    "Broken Access Control":            {"cwe": ["CWE-639", "CWE-862"], "owasp_api": ["API1:2023", "API5:2023"], "owasp_top10": "A01:2021", "confidence": "medium"},
    "JWT alg=none":                     {"cwe": ["CWE-347"], "owasp_api": ["API2:2023"], "owasp_top10": "A07:2021", "confidence": "high"},
    "Missing Security Headers":         {"cwe": ["CWE-693"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "high"},
    "Missing CSP":                      {"cwe": ["CWE-693"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "high"},
    "Missing HSTS":                     {"cwe": ["CWE-693"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "high"},
    "Weak TLS Version":                 {"cwe": ["CWE-326"], "owasp_api": ["API8:2023"], "owasp_top10": "A02:2021", "confidence": "high"},
    "TLS Certificate Expired":          {"cwe": ["CWE-295"], "owasp_api": ["API8:2023"], "owasp_top10": "A02:2021", "confidence": "high"},
    "TLS Certificate Expiring Soon":    {"cwe": ["CWE-295"], "owasp_api": ["API8:2023"], "owasp_top10": "A02:2021", "confidence": "high"},
    "TLS Certificate Untrusted":        {"cwe": ["CWE-295"], "owasp_api": ["API8:2023"], "owasp_top10": "A02:2021", "confidence": "high"},
    "Sensitive Data Exposure":          {"cwe": ["CWE-200"], "owasp_api": ["API3:2023"], "owasp_top10": "A01:2021", "confidence": "high"},
    "Open CORS":                        {"cwe": ["CWE-942"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "high"},
    "Lack of Rate Limiting":            {"cwe": ["CWE-770"], "owasp_api": ["API4:2023"], "owasp_top10": "A04:2021", "confidence": "medium"},
    "Lack of CAPTCHA":                  {"cwe": ["CWE-307"], "owasp_api": ["API2:2023"], "owasp_top10": "A07:2021", "confidence": "medium"},
    "Information Leak via Errors":      {"cwe": ["CWE-209"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "high"},
    "HTTP without HTTPS":               {"cwe": ["CWE-319"], "owasp_api": ["API8:2023"], "owasp_top10": "A02:2021", "confidence": "high"},
    "Missing CSRF Protection":          {"cwe": ["CWE-352"], "owasp_api": ["API8:2023"], "owasp_top10": "A01:2021", "confidence": "low"},
    "Unsafe HTTP Methods":              {"cwe": ["CWE-650"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "medium"},
    "Missing Content-Type Validation":  {"cwe": ["CWE-20"],  "owasp_api": ["API8:2023"], "owasp_top10": "A04:2021", "confidence": "low"},
    "Dependency Manifest Exposed":      {"cwe": ["CWE-200"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "high"},
    "Vulnerable Dependency (OSV)":      {"cwe": ["CWE-1104"], "owasp_api": ["API8:2023"], "owasp_top10": "A06:2021", "confidence": "high"},
    "Business Logic Error":             {"cwe": ["CWE-840"], "owasp_api": ["API4:2023"], "owasp_top10": "A04:2021", "confidence": "low"},
    "Missing Pagination":               {"cwe": ["CWE-770"], "owasp_api": ["API4:2023"], "owasp_top10": "A04:2021", "confidence": "medium"},
    "Mass Assignment":                  {"cwe": ["CWE-915"], "owasp_api": ["API3:2023"], "owasp_top10": "A04:2021", "confidence": "low"},
    "GraphQL Introspection":            {"cwe": ["CWE-200"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "medium"},
    "Hidden Path":                      {"cwe": ["CWE-200"], "owasp_api": ["API8:2023"], "owasp_top10": "A05:2021", "confidence": "low"},
}


def get_vuln_info(vuln_type: str) -> Dict:
    """Описание + рекомендация + классификация (CWE/OWASP/confidence)."""
    info = dict(VULN_DESCRIPTIONS.get(vuln_type, {
        "plain": "Уязвимость без дополнительного описания.",
        "recommendation": "Проверьте документацию по безопасности."
    }))
    meta = VULN_META.get(vuln_type, {})
    info.setdefault("cwe", meta.get("cwe", []))
    info.setdefault("owasp_api", meta.get("owasp_api", []))
    info.setdefault("owasp_top10", meta.get("owasp_top10", ""))
    info.setdefault("confidence", meta.get("confidence", "medium"))
    return info