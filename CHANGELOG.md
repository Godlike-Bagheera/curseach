# Changelog

## Unreleased

### Бюджет и покрытие
- Per-check квоты бюджета запросов: «прожорливые» проверки (SQLi/SSRF) больше не съедают весь бюджет раньше остальных.
- Статистика покрытия в отчёте: «Покрытие: эндпоинтов N, поверхностей M, запросов X/бюджет Y» (HTML/PDF, история).

### Операционные фичи
- Webhook-уведомления: POST JSON-сводки по завершении скана (таймаут 5s, 1 retry, ошибка не валит скан).

### Прочее
- Docker base-image запинен по digest; pip install --require-hashes (hash-locked requirements.txt/dev).
- httpx2 проверен: легитимный преемник httpx (Pydantic / Tom Christie), нужен starlette TestClient — оставлен.
- Генерация секции проверок about.html из единого источника (scripts/gen_about.py, CI-гейт --check).
- Auth-профили: bearer/form/apikey, refresh при 401; таблица auth_profiles + CRUD /auth-profiles + выбор/сохранение в UI.
- Расписания (повторные сканы, тик/минута), проекты (мульти-цели), тренд-график по истории (/history/trend, Chart.js).
- i18n: переключатель EN/RU в шапке (static/i18n.js, data-i18n, localStorage), каркас + ключевой экран.

## 1.2.0

### Точность детектирования
- BFLA эмитит точный тип «Broken Function Level Authorization» (API5).
- TLS Certificate Expired достижим; Mass Assignment — read-back; Hidden Paths — baseline/documented.
- SCA — валидация манифеста; OSV — CVSS-векторы и exact-pins; IDOR — нормализация динамики.
- Пагинация ищет коллекции; Unsafe Methods — TRACE/WebDAV; HSTS только на https.

### Безопасность сканера
- SSRF: IPv4-mapped IPv6 нормализация, fail-closed DNS; cookie secure за прокси + sliding; logout POST.
- CSP form-action, Referrer/Permissions-Policy, HSTS(env); CSV/XLSX formula-injection; SARIF evidence-редакция+helpUri+fingerprints; WeasyPrint url_fetcher.

### Учебная цель
- Новые симулированные уязвимости (XSS, Command Injection, GraphQL, SCA, Pagination, Mass Assignment, CSRF, Unsafe Methods, Content-Type, Hidden Paths, Open CORS); демо-seed 0.

### Качество
- Режим скана в истории; единый источник VERSION/подписей/оценки; .ruff_cache удалён; ruff clean.
