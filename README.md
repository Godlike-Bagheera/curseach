# curseach — DevSecOps-сканер API

Учебный сканер безопасности API + намеренно уязвимая цель («Damn Vulnerable API»)
в одном репозитории. Сканер ходит по OpenAPI-спеке цели, прогоняет ~25 проверок
(SQLi, XSS, IDOR/BOLA/BFLA, JWT alg=none, заголовки, TLS, CORS, rate-limit и др.)
и собирает отчёты: HTML, PDF (WeasyPrint), CSV, XLSX, SARIF, ZIP.

> ⚠️ Только для учебных целей и сканирования СВОИХ сервисов. Не используйте
> против чужих систем без письменного разрешения.

## Быстрый старт

    python start.py

Поднимет уязвимую цель (http://127.0.0.1:8000, Swagger — /docs) и сканер
(http://127.0.0.1:8001). Зависимости доустановятся автоматически.

### Docker

    docker build -t curseach .
    docker run --rm -p 8000:8000 -p 8001:8001 curseach

## Вход в сканер

| Роль  | Логин | Пароль | Права                         |
|-------|-------|--------|-------------------------------|
| admin | admin | admin  | сканирование, история, отчёты |
| guest | guest | guest  | только просмотр «О проекте»   |

Креды учебные, захардкожены в scanner/config.py — для публичного деплоя
обязательно поменяйте их и настройте ALLOWED_HOSTS.

## Как сканировать

1. Войдите как admin.
2. Укажите URL цели (для встроенной цели — http://127.0.0.1:8000).
3. Для проверок контроля доступа задайте два аккаунта цели: alice / alice123 и bob / bob123.
4. Выберите режим (quick / full / custom) и запустите — логи идут live по WebSocket.

## Отчёты

- HTML-отчёт по задаче и по записи истории
- PDF на сервере (WeasyPrint, без колонтитулов браузера)
- CSV / XLSX / JSON / SARIF (для GitHub Code Scanning) / ZIP-бандл

## Тесты

    pip install -r requirements-dev.txt
    pytest -q

## Структура

- main.py — уязвимая цель (FastAPI), профиль уязвимостей рандомизируется на скан
- scanner/ — веб-приложение сканера (app, config, security, tasks, reporting, routes)
- checks/ — проверки безопасности
- templates/, static/ — UI
- database.py — история сканов (SQLite, WAL)

## Лицензия

MIT (учебный проект).
