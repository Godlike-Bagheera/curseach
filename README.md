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

Образ содержит всё окружение: Python 3.12, зависимости по хеш-пинам,
Playwright + Chromium для PDF-экспорта. Внутри контейнера одной командой
(`start.py`) поднимаются **оба сервиса**: учебная цель (порт 8000) и сканер
(порт 8001). Контейнер работает от непривилегированного пользователя `appuser`
(uid **10001**) — это важно для bind-mount, см. ниже.

### Сборка

    docker build -t curseach .

**Первый build занимает 5–10 минут:** внутри образа через
`playwright install --with-deps chromium` скачивается Chromium (~150 МБ) и его
системные библиотеки (~200 МБ apt-пакетов). Итоговый размер образа — ~800–900 МБ.
Последующие сборки используют layer cache и проходят за секунды, если
`requirements.txt` и `Dockerfile` не менялись.

**Сборка либо проходит целиком, либо падает.** Установка Chromium — часть
`RUN`-цепочки через `&&`, поэтому если нет доступа к apt-репозиториям или CDN
Playwright (например, за корпоративным прокси), `docker build` завершится
ошибкой на шаге `playwright install --with-deps chromium`. «Образа без PDF»
не получится — для сборки нужен интернет.

### Запуск

    docker run -d --name curseach \
      -p 8000:8000 -p 8001:8001 \
      -v curseach_data:/data \
      curseach

Открыть http://127.0.0.1:8001, войти как `admin / admin`.
Логи: `docker logs -f curseach`. Остановить: `docker stop curseach`.
Нужен запуск на переднем плане — вместо `-d --name curseach` подставьте `--rm`
(Ctrl+C остановит контейнер).

### Порты

| Порт | Что |
|---|---|
| `8000` | Уязвимая цель (только для сканирования изнутри, наружу не выставлять) |
| `8001` | Сам сканер (веб-интерфейс + API) |

Оба сервиса живут в **одном контейнере**, поэтому встроенную цель сканируйте
прямо по `http://127.0.0.1:8000` — это адрес внутри контейнера, он работает.
Публиковать порт 8000 наружу не обязательно: `-p 8000:8000` можно убрать,
цель всё равно останется доступна сканеру.

Если цель запущена **на хосте**, вне контейнера, то `127.0.0.1` из контейнера
её не достанет — используйте `http://host.docker.internal:<порт>` (Docker
Desktop), а на Linux добавьте к `docker run` флаг
`--add-host=host.docker.internal:host-gateway`.

### Переменные окружения

Задаются через `-e`:

    docker run -d --name curseach \
      -p 8001:8001 \
      -v curseach_data:/data \
      -e SCANNER_ADMIN_PASSWORD=strong-admin-pass \
      -e SCANNER_GUEST_PASSWORD=strong-guest-pass \
      curseach

Полный список — в разделе «Переменные окружения» ниже. В образе уже
предустановлены дефолты для контейнера: `SCANNER_HOST=0.0.0.0`,
`SCANNER_PORT=8001`, `API_HOST=0.0.0.0`, `API_PORT=8000`,
`SCANNER_DB_PATH=/data/scans.db`, `SCANNER_ALLOW_PRIVATE_TARGETS=1`
и `ALLOWED_HOSTS` для localhost и Codespaces.

**Открываете сканер не через localhost?** Если заходить по IP сервера или
домену (`http://192.168.1.50:8001`, `https://scanner.example.com`), добавьте
этот хост в `ALLOWED_HOSTS`, иначе вход вернёт `403 Origin not allowed`:

    -e ALLOWED_HOSTS="127.0.0.1,localhost,192.168.1.50,scanner.example.com"

### Volume `/data`

История сканов хранится в SQLite-файле `scans.db` в `/data`. **Volume обязателен**,
если хотите сохранять историю между перезапусками контейнера. Без него `docker rm`
уничтожит базу.

Рекомендуется именованный volume — Docker создаёт его сам и с нужными правами:

    docker run -d --name curseach -v curseach_data:/data ...

Bind-mount папки с хоста тоже работает, но контейнер живёт под uid **10001**,
и папка должна быть доступна ему на запись. Несуществующую папку Docker создаёт
от root — тогда сканер **упадёт на старте** с
`sqlite3.OperationalError: unable to open database file`. На Linux подготовьте
папку заранее:

    mkdir -p data && sudo chown 10001:10001 data
    docker run -d --name curseach -v "$PWD/data:/data" ...

### Healthcheck

В Dockerfile встроен `HEALTHCHECK`: раз в 30 секунд опрашивается `GET /healthz`
(без авторизации) на порту сканера. Проверить статус контейнера из примера выше:

    docker inspect --format='{{.State.Health.Status}}' curseach

`healthy` — сканер готов к работе.

### Проверка, что PDF работает в контейнере

    docker run --rm curseach python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage']); print('Chromium OK'); b.close(); p.stop()"

Если выведет `Chromium OK` — PDF-экспорт в контейнере работает. Флаги
`--no-sandbox --disable-dev-shm-usage` — ровно те, что использует сам сканер
(`scanner/pdf.py`): они нужны для Chromium под non-root в контейнере.

### Docker Compose (опционально)

Если удобнее через compose, создайте `docker-compose.yml`:

    services:
      curseach:
        build: .
        ports:
          - "8000:8000"
          - "8001:8001"
        volumes:
          - curseach_data:/data
        environment:
          SCANNER_ADMIN_PASSWORD: change-me
          SCANNER_GUEST_PASSWORD: change-me
        restart: unless-stopped

    volumes:
      curseach_data:

Запуск: `docker compose up -d`, логи: `docker compose logs -f`, остановка:
`docker compose down` (том с историей сохраняется; `down -v` удалит и его).

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
- `Dockerfile`, `.devcontainer/`, `.github/workflows/` — контейнер, Codespaces, CI и Security Scan

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
