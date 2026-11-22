# curseach — DevSecOps-сканер API

[![CI](https://github.com/Godlike-Bagheera/curseach/actions/workflows/ci.yml/badge.svg)](https://github.com/Godlike-Bagheera/curseach/actions/workflows/ci.yml)
[![Security Scan](https://github.com/Godlike-Bagheera/curseach/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Godlike-Bagheera/curseach/actions/workflows/security-scan.yml)

Учебный DAST-сканер безопасности API + намеренно уязвимая цель («Damn Vulnerable API»)
в одном репозитории. Сканер читает OpenAPI-спеку цели и прогоняет **27 проверок**
(SQLi, XSS, IDOR/BOLA/BFLA, JWT alg=none, заголовки, TLS/сертификат, CORS, rate-limit,
SCA через OSV.dev и др.), показывая live-логи по WebSocket и собирая отчёты
HTML / PDF / CSV / XLSX / SARIF / ZIP — с **evidence (запрос/ответ), CWE и OWASP API Top 10**.

> ⚠️ Только для учебных целей и сканирования СВОИХ сервисов. Не используйте
> против чужих систем без письменного разрешения.

## Возможности

- **Полное покрытие OpenAPI**: path-, query- и body-параметры, методы GET/POST/PUT/PATCH/DELETE
  (тела генерируются из JSON-схем requestBody).
- **Параллельное сканирование**: `asyncio.gather` + семафор, общий бюджет запросов,
  RPS-лимит и таймаут — быстро и «вежливо» к цели.
- **Evidence + классификация**: каждая находка несёт запрос/ответ, уверенность (confidence),
  CWE и OWASP API Top 10 / OWASP Top 10; дубликаты схлопываются.
- **Настоящий SCA**: пиннутые версии из манифестов сверяются с базой [OSV.dev](https://osv.dev) (CVE/GHSA).
- **Отмена скана** кнопкой «Остановить», лимит одновременных сканов.
- **SARIF → GitHub Security tab**: workflow self-scan сканирует учебную цель и грузит SARIF.
- **Детерминированная цель**: заголовок `X-Scan-Seed` фиксирует профиль уязвимостей (воспроизводимые тесты).
- Anti-SSRF (включая пиннинг проверенного IP от DNS-rebinding), CSRF-Origin-политика, CSP,
  PBKDF2-пароли, HttpOnly-cookie, rate-limit логина.
- **Справочник `/vulns`**: EN + RU-название и смысл популярных уязвимостей, рекомендации,
  CWE/OWASP API Top 10 и реестр всех 27 проверок; поиск без перезагрузки, доступен гостю.
- **Фильтр истории по датам**: период «С/По», пресеты «Сегодня/7/30 дней», счётчик,
  экспорт XLSX за выбранный период; выбор сохраняется в localStorage.
- **JetBrains Mono self-hosted** (`static/fonts/`) — строгая CSP без внешних CDN, работа офлайн.

## Быстрый старт

    python start.py

Поднимет уязвимую цель (http://127.0.0.1:8000, Swagger — `/docs`) и сканер
(http://127.0.0.1:8001). Зависимости доустановятся автоматически.

### Docker

    docker build -t curseach .
    docker run --rm -p 8000:8000 -p 8001:8001 curseach

## Вход в сканер

| Роль  | Логин | Пароль | Права                         |
|-------|-------|--------|-------------------------------|
| admin | admin | admin  | сканирование, история, отчёты |
| guest | guest | guest  | только просмотр «О проекте»   |

Креды учебные. Для публичного деплоя **обязательно** переопределите их через env
(`SCANNER_ADMIN_PASSWORD`, `SCANNER_GUEST_PASSWORD`) и настройте `ALLOWED_HOSTS`.

## Как сканировать

1. Войдите как admin.
2. Укажите URL цели (для встроенной — `http://127.0.0.1:8000`).
3. Для проверок контроля доступа задайте два аккаунта цели: `alice / alice123` и `bob / bob123`.
4. Выберите режим (quick / full / custom) и запустите. Логи идут live, скан можно остановить.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `SCANNER_ADMIN_PASSWORD` / `SCANNER_GUEST_PASSWORD` | admin / guest | пароли входа в сканер |
| `SCAN_CONCURRENCY` | 8 | одновременных запросов внутри скана |
| `SCAN_MAX_REQUESTS` | 1500 | бюджет запросов на скан |
| `SCAN_RPS` | 20 | запросов в секунду (0 — без лимита) |
| `SCAN_TOTAL_TIMEOUT` | 300 | общий таймаут скана, сек |
| `MAX_CONCURRENT_SCANS` | 3 | одновременных сканов на процесс |
| `SCAN_PIN_DNS` | 1 | пиннить проверенный IP (anti-DNS-rebinding) |
| `SCANNER_ALLOW_PRIVATE_TARGETS` | 1 | разрешить private/loopback цели (учебный стенд) |
| `ALLOWED_HOSTS` | localhost + Codespaces | разрешённые Origin/хосты |
| `SCANNER_DB_PATH` | scans.db | файл истории (SQLite, WAL) |

**Важно:** сессии и задачи хранятся в памяти процесса — запускайте сканер
в **один воркер** (`uvicorn --workers 1`, как в `start.py`/Docker).

## Отчёты

HTML (с evidence и классификацией), PDF на сервере (WeasyPrint, без колонтитулов),
CSV / XLSX (колонки confidence/CWE/OWASP/evidence), JSON, SARIF 2.1.0
(теги CWE/OWASP, security-severity) и ZIP-бандл со всем сразу.

## Тесты и CI

    pip install -r requirements-dev.txt
    pytest -q

Юнит-тесты проверок (httpx.MockTransport, без сети) + **e2e-тест**: поднимается
учебная цель и сканируется движком с фиксированным seed. В CI: ruff, mypy,
coverage, smoke-import. Отдельный workflow **Security Scan** сканирует цель
и загружает SARIF во вкладку **Security** репозитория.

## Структура

- `main.py` — уязвимая цель (FastAPI), профиль уязвимостей рандомизируется на скан (или фиксируется seed-ом)
- `scanner/` — веб-приложение сканера: `app`, `config`, `security` (anti-SSRF/сессии), `tasks` (движок),
  `reporting`, `pdf` (WeasyPrint), `vuln_guide` (справочник `/vulns`), `routes/` (auth/scan/history/misc)
- `checks/` — 27 проверок + поверхности атаки из OpenAPI (`surface.py`), описания и CWE/OWASP (`descriptions.py`)
- `scripts/self_scan.py` — self-scan для CI (SARIF)
- `templates/` — index, login, `vulns` (справочник), отчёты и диаграмма
- `static/` — UI: `style.css`, `fonts.css` + `fonts/` (self-hosted JetBrains Mono), `script.js`,
  `history_filter.*` (фильтр истории), `vulns.js` (поиск по справочнику)
- `database.py` — история сканов (SQLite, WAL)
- `tests/` — pytest: юнит-тесты проверок и роутов + e2e-скан
- `Dockerfile`, `.devcontainer/`, `.github/workflows/` — контейнер, Codespaces, CI и Security Scan

## Безопасность при публичном деплое

Сканер по умолчанию локальный (`127.0.0.1`, admin/admin). Если выставляете его наружу:

- задайте `SCANNER_ADMIN_PASSWORD` и `SCANNER_GUEST_PASSWORD` (start.py предупредит, если забыли);
- `SCANNER_COOKIE_SECURE=1`, `SCANNER_HSTS=1`, за TLS-прокси — `SCANNER_TRUST_PROXY=1`;
- `SCANNER_ALLOW_PRIVATE_TARGETS=0` — строгая SSRF-защита (fail-closed);
- ограничьте `ALLOWED_HOSTS` своим доменом.

Учебную цель (`main.py`) **не публикуйте** — она уязвима по замыслу. Подробнее: [SECURITY.md](SECURITY.md).

## Покрытие проверок учебной целью

Все 27 проверок демонстрируются на встроенной цели (кроме TLS — нужна https-цель).
Матрица «проверка ↔ эндпоинт ↔ условие»: [docs/COVERAGE.md](docs/COVERAGE.md).
Демо-режим «всё включено»: заголовок `X-Scan-Seed: 0`.

## Лицензия

MIT — см. [LICENSE](LICENSE).
