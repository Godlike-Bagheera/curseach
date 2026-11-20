# Матрица покрытия: проверка ↔ учебная цель

27 проверок сканера и то, чем они exercised на встроенной цели (`main.py`).

| Проверка | Эндпоинт цели | Условие |
|---|---|---|
| `check_sqli` | `/api/users/{user_id}` | профиль sqli_enabled; error/boolean-based |
| `check_xss` | `/api/echo?msg=` | всегда; HTML-эхо без экранирования |
| `check_hidden_paths` | `/admin, /.env, /backup, /metrics, /server-status` | всегда; вне OpenAPI (include_in_schema=False) |
| `check_idor` | `/api/orders/{id}, /api/system/keys` | профиль idor_enabled |
| `check_idor_auth` | `статические эндпоинты (auth vs аноним)` | профиль idor_enabled + токен |
| `check_cross_user_idor` | `/api/orders/{order_id}` | idor_enabled + два аккаунта (alice/bob) |
| `check_bfla` | `/api/admin/users` | профиль bfla_enabled + два аккаунта |
| `check_jwt_none` | `/api/reports/{report_id}` | профиль jwt_none_enabled |
| `check_security_headers` | `/` | рандомизированные заголовки; seed 0 → все отсутствуют |
| `check_sensitive_data` | `/api/system/keys` | профиль idor_enabled (AWS-ключ в ответе) |
| `check_cors` | `/ (ACAO: *)` | всегда; CORS middleware allow_origins=* |
| `check_rate_limiting` | `/ (50 запросов)` | всегда; rate-limit отсутствует |
| `check_command_injection` | `/api/ping?host=` | всегда; симулированный вывод uid= (без exec) |
| `check_error_leak` | `/api/users/{id} (невалидный ввод)` | частично; зависит от текста ошибки |
| `check_http_only` | `http:// цель` | всегда; цель на http |
| `check_csrf` | `/api/session/action, /api/profile` | всегда; state-changing POST без CSRF-токена |
| `check_unsafe_methods` | `OPTIONS / (Allow: TRACE)` | всегда; TRACE в Allow |
| `check_content_type_validation` | `/api/legacy (text/plain)` | всегда; принимает любой Content-Type |
| `check_sca` | `/requirements.txt` | всегда; манифест с устаревшими пиннами |
| `check_captcha` | `/api/auth/login (10 неверных попыток)` | всегда; CAPTCHA/блокировки нет |
| `check_business_logic` | `/api/orders/{id} (id=-1)` | профиль business_logic_enabled |
| `check_pagination` | `/api/products (250 элементов)` | всегда; limit=10000 отдаёт всё |
| `check_tls_version` | `https-цель` | НЕ на встроенной цели (http); нужен внешний https |
| `check_mass_assignment` | `/api/profile (role/is_admin)` | всегда; read-back подтверждает присвоение |
| `check_graphql_introspection` | `/graphql` | всегда; интроспекция без auth |
| `check_osv_sca` | `/requirements.txt → OSV API` | всегда; нужен доступ к api.osv.dev |
| `check_ssrf` | `/api/fetch-url` | профиль ssrf_enabled; симулированные internal/metadata |

## Примечания

- **Демо-seed `0`** (`X-Scan-Seed: 0`) включает все профильные уязвимости и убирает
  заголовки безопасности — удобно показать все проверки сразу.
- `check_tls_version` требует **https**-цель: встроенная цель на http, поэтому эта
  проверка демонстрируется на внешнем https-адресе.
- `check_osv_sca` ходит в **api.osv.dev** — нужна сеть; при недоступности gracefully
  возвращает пусто (не падает).
- Симулированные уязвимости (Command Injection, SSRF) **не выполняют** реальных
  опасных действий — вывод canned, безопасно для обучения.

## Новые проверки (PR #34)

| Проверка | Эндпоинт цели | Условие |
|---|---|---|
| ```check_path_traversal``` | ```/api/file?name=``` | всегда; симулированное чтение /etc/passwd |
| ```check_open_redirect``` | ```/api/redirect?next=``` | всегда; 302 на произвольный URL |
| ```check_cookie_flags``` | ```/api/session/login``` | всегда; cookie без Secure/HttpOnly/SameSite |
| ```check_stored_xss``` | ```/api/comments``` | всегда; POST→GET HTML без экранирования |
| ```check_jwt_exp``` | ```/api/reports/{id}``` | профиль jwt_none_enabled; истёкший exp |
