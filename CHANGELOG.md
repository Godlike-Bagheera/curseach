# Changelog

## Unreleased

### Точность детектирования (6 ложных срабатываний)
- SQLi: HTTP 500 на payload флагуется только при не-500 baseline (безобидное «1» в тот же параметр); error-text детекция сохранена.
- IDOR: параметрические эндпоинты с security: [] в спеке (публичный каталог) пропускаются.
- CSRF: Bearer-only API без cookies не флагуется; cookie-сессии детектируются как раньше.
- CAPTCHA: только реальные login-пути (404/405 отсекаются; считаются ответы валидации 400/401/422).
- HTTP without HTTPS: LOW для loopback/приватных хостов, MEDIUM для публичных.
- OS Command Injection: сигнатуры uid=+gid= / root:x:0:0 / Windows вместо голого «root:».
- Регрессионные тесты: tests/test_falsepositive_fixes.py (здоровый сервис → нет находки, уязвимый → есть).

### Исправления запуска
- start.py: зависимости ставятся только из готовых wheels (--only-binary :all:) — компиляция и python3-devel/gcc не нужны; fallback на исходники и понятная диагностика (Python.h → команда установки заголовков под дистрибутив).
- requirements.txt: добавлены sha256 manylinux-wheels для Python 3.11 (x86_64/aarch64) — запуск на системном Python 3.11 без сборки brotli/cffi/httptools/pillow/uvloop.

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
- i18n расширен на экраны входа и справочника /vulns (+ placeholder поиска), подписи auth/истории/планировщика; window.I18N.t() для будущих динамических строк.

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
