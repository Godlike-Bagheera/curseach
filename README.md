# curseach — DevSecOps-сканер API

[![CI](https://github.com/Godlike-Bagheera/curseach/actions/workflows/ci.yml/badge.svg)](https://github.com/Godlike-Bagheera/curseach/actions/workflows/ci.yml)
[![Security Scan](https://github.com/Godlike-Bagheera/curseach/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Godlike-Bagheera/curseach/actions/workflows/security-scan.yml)

Учебный DAST-сканер безопасности API + намеренно уязвимая цель («Damn Vulnerable API»)
в одном репозитории. Сканер читает OpenAPI-спеку цели и прогоняет **34 проверки**
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
- **Серверный PDF** через Playwright/Chromium — работает на Windows, Linux и в Docker без
  системных библиотек (GTK/Pango больше не нужны). Chromium скачивается автоматически
  при первом запуске `start.py` или собирается в Docker-образе.
- Anti-SSRF (включая пиннинг проверенного IP от DNS-rebinding), CSRF-Origin-политика, CSP,
  PBKDF2-пароли, HttpOnly-cookie, rate-limit логина.
- **Справочник `/vulns`**: EN + RU-название и смысл популярных уязвимостей, рекомендации,
  CWE/OWASP API Top 10 и реестр всех проверок; поиск без перезагрузки, доступен гостю.
- **Фильтр истории по датам**: период «С/По», пресеты «Сегодня/7/30 дней», счётчик,
  экспорт XLSX за выбранный период; выбор сохраняется в localStorage.
- **JetBrains Mono self-hosted** (`static/fonts/`) — строгая CSP без внешних CDN, работа офлайн.

## Быстрый старт

    python start.py

Поднимет уязвимую цель (http://127.0.0.1:8000, Swagger — `/docs`) и сканер
(http://127.0.0.1:8001). Зависимости доустановятся автоматически.

**Первый запуск:** `start.py` дополнительно скачает Chromium (~150 МБ) для PDF-экспорта
в `%LOCALAPPDATA%\ms-playwright` (Windows) или `~/.cache/ms-playwright` (Linux/macOS).
Это разовая операция. Если интернета нет — сканер запустится, все отчёты кроме PDF
будут работать; чтобы доустановить Chromium вручную: `python -m playwright install chromium`.

## Docker

Стенд разворачивается на любой машине с Docker (Linux-сервер Ubuntu/Debian,
macOS, Windows с Docker Desktop) — Python, зависимости и Chromium ставить
не нужно, всё уже внутри образа. В одном контейнере поднимаются оба сервиса:
сканер (порт 8001) и учебная цель (порт 8000, доступна сканеру изнутри контейнера).

### Требования

- Docker Engine 20.10+
- Docker Compose V2

### Запуск

    git clone https://github.com/Godlike-Bagheera/curseach.git
    cd curseach
    docker compose up -d --build

Первая сборка занимает 5–10 минут: внутри образа скачивается Chromium (~150 МБ)
и его системные библиотеки (~200 МБ apt-пакетов), итоговый образ — ~800–900 МБ.
Повторные сборки проходят за секунды благодаря кэшу слоёв. Для сборки нужен
интернет: установка Chromium — часть `RUN`-цепочки через `&&`, поэтому без
доступа к apt-репозиториям или CDN Playwright сборка упадёт на шаге
`playwright install --with-deps chromium` («образа без PDF» не получится).

### Доступ

| Что | Адрес |
|---|---|
| Сканер (веб-интерфейс) | http://127.0.0.1:8001 — вход `admin / admin` |
| Учебная цель | http://127.0.0.1:8000 — этот адрес вводите в сканер |

Оба сервиса живут в одном контейнере, поэтому адрес цели `127.0.0.1:8000`
работает прямо из интерфейса сканера. Наружу порт 8000 по умолчанию
**не публикуется** — это намеренно уязвимое приложение. Если он всё же нужен
снаружи, раскомментируйте строку `8000:8000` в `compose.yaml`.

### Запуск на сервере (доступ по IP/домену)

Если открывать сканер по адресу сервера (`http://<IP_СЕРВЕРА>:8001`), добавьте
этот хост в `ALLOWED_HOSTS` — иначе вход вернёт `403 Origin not allowed`.
Всё настраивается через файл `.env` рядом с `compose.yaml`:

    ALLOWED_HOSTS=127.0.0.1,localhost,<IP_СЕРВЕРА>
    SCANNER_ADMIN_PASSWORD=strong-admin-pass
    SCANNER_GUEST_PASSWORD=strong-guest-pass

Затем `docker compose up -d`. Пароли по умолчанию — `admin` / `guest`,
для публичного сервера обязательно смените их. Полный список переменных —
в разделе «Переменные окружения» ниже, про защиту — в «Безопасность
при публичном деплое».

### Остановка и перезапуск

    docker compose stop     # пауза с сохранением данных
    docker compose start    # продолжить работу
    docker compose down     # удалить контейнер (история сканов в томе сохраняется)
    docker compose down -v  # удалить контейнер И историю сканов

Логи: `docker compose logs -f`. Статус: `docker compose ps` — в колонке STATUS
должно быть `healthy` (в образ встроен `HEALTHCHECK` на `GET /healthz`
без авторизации, раз в 30 секунд).

### Ручной запуск без compose (альтернатива)

    docker build -t curseach .
    docker run -d --name curseach \
      -p 8001:8001 \
      -v curseach_data:/data \
      curseach

Логи: `docker logs -f curseach`, остановить: `docker stop curseach`.
Нужен запуск на переднем плане — вместо `-d --name curseach` подставьте `--rm`.
Переменные задаются через `-e` (например, `-e SCANNER_ADMIN_PASSWORD=...`).
В образе уже предустановлены дефолты для контейнера: `SCANNER_HOST=0.0.0.0`,
`SCANNER_PORT=8001`, `API_HOST=0.0.0.0`, `API_PORT=8000`,
`SCANNER_DB_PATH=/data/scans.db`, `SCANNER_ALLOW_PRIVATE_TARGETS=1`.

### Volume `/data` и bind-mount

История сканов — SQLite-файл `/data/scans.db`. И `compose.yaml`, и пример выше
используют именованный том `curseach_data`: он переживает `docker rm` /
`docker compose down` и создаётся с нужными правами автоматически.

Bind-mount папки с хоста тоже работает, но контейнер живёт под
непривилегированным пользователем `appuser` (uid **10001**), и папка должна
быть доступна ему на запись. Несуществующую папку Docker создаёт от root —
тогда сканер **упадёт на старте** с
`sqlite3.OperationalError: unable to open database file`. На Linux подготовьте
папку заранее:

    mkdir -p data && sudo chown 10001:10001 data
    docker run -d --name curseach -p 8001:8001 -v "$PWD/data:/data" curseach

### Сканирование целей вне контейнера

`127.0.0.1` из контейнера — это сам контейнер. Цель, запущенную на хосте,
сканируйте через `http://host.docker.internal:<порт>` (Docker Desktop),
а на Linux добавьте сервису в `compose.yaml`:

    extra_hosts:
      - "host.docker.internal:host-gateway"

(при ручном запуске — флаг `--add-host=host.docker.internal:host-gateway`).

### Проверка, что PDF работает в контейнере

После сборки (`docker compose build` или `docker build`):

    docker run --rm curseach python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage']); print('Chromium OK'); b.close(); p.stop()"

Если выведет `Chromium OK` — PDF-экспорт в контейнере работает. Флаги
`--no-sandbox --disable-dev-shm-usage` — ровно те, что использует сам сканер
(`scanner/pdf.py`): они нужны для Chromium под non-root в контейнере.

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
| `SCAN_MAX_REQUESTS` | 3000 | бюджет запросов на скан |
| `SCAN_RPS` | 20 | запросов в секунду (0 — без лимита) |
| `SCAN_TOTAL_TIMEOUT` | 300 | общий таймаут скана, сек |
| `MAX_CONCURRENT_SCANS` | 3 | одновременных сканов на процесс |
| `SCAN_PIN_DNS` | 1 | пиннить проверенный IP (anti-DNS-rebinding) |
| `SCANNER_ALLOW_PRIVATE_TARGETS` | 1 | разрешить private/loopback цели (учебный стенд) |
| `ALLOWED_HOSTS` | localhost + Codespaces | разрешённые Origin/хосты |
| `SCANNER_DB_PATH` | scans.db | файл истории (SQLite, WAL); в образе — `/data/scans.db` |
| `SCANNER_HOST` / `SCANNER_PORT` | 127.0.0.1 / 8001 | адрес и порт сканера (в образе host — `0.0.0.0`) |
| `API_HOST` / `API_PORT` | 127.0.0.1 / 8000 | адрес и порт учебной цели (в образе host — `0.0.0.0`) |

**Важно:** сессии и задачи хранятся в памяти процесса — запускайте сканер
в **один воркер** (`uvicorn --workers 1`, как в `start.py`/Docker).

## Отчёты

HTML (с evidence и классификацией), PDF на сервере (Playwright/Chromium, без колонтитулов),
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
  `reporting`, `pdf` (Playwright), `vuln_guide` (справочник `/vulns`), `routes/` (auth/scan/history/misc)
- `checks/` — 27 файлов проверок (34 отдельных проверки) + поверхности атаки из OpenAPI (`surface.py`),
  описания и CWE/OWASP (`descriptions.py`)
- `scripts/self_scan.py` — self-scan для CI (SARIF)
- `templates/` — index, login, `vulns` (справочник), отчёты и диаграмма
- `static/` — UI: `style.css`, `fonts.css` + `fonts/` (self-hosted JetBrains Mono), `script.js`,
  `history_filter.*` (фильтр истории), `vulns.js` (поиск по справочнику)
- `database.py` — история сканов (SQLite, WAL)
- `tests/` — pytest: юнит-тесты проверок и роутов + e2e-скан
- `Dockerfile`, `compose.yaml`, `.devcontainer/`, `.github/workflows/` — контейнер, Compose, Codespaces, CI и Security Scan

## Безопасность при публичном деплое

Сканер по умолчанию локальный (`127.0.0.1`, admin/admin). Если выставляете его наружу:

- задайте `SCANNER_ADMIN_PASSWORD` и `SCANNER_GUEST_PASSWORD` (start.py предупредит, если забыли);
- `SCANNER_COOKIE_SECURE=1`, `SCANNER_HSTS=1`, за TLS-прокси — `SCANNER_TRUST_PROXY=1`;
- `SCANNER_ALLOW_PRIVATE_TARGETS=0` — строгая SSRF-защита (fail-closed);
- ограничьте `ALLOWED_HOSTS` своим доменом.

Учебную цель (`main.py`) **не публикуйте** — она уязвима по замыслу. Подробнее: [SECURITY.md](SECURITY.md).

## Покрытие проверок учебной целью

Все 34 проверки демонстрируются на встроенной цели (кроме TLS — нужна https-цель).
Матрица «проверка ↔ эндпоинт ↔ условие»: [docs/COVERAGE.md](docs/COVERAGE.md).
Демо-режим «всё включено»: заголовок `X-Scan-Seed: 0`.

## Лицензия

MIT — см. [LICENSE](LICENSE).
