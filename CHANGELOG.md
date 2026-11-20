# Changelog

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
