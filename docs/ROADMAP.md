# Roadmap: улучшения сканера

## Уже сделано

- **Точность детектирования (A)** и **hardening сканера (B)** — PR #31, #32.
- **Учебная цель** покрывает почти все проверки (C) — PR #31.
- **Качество/CI/доки/a11y (E/F)**, CORS reflection, качество CSP (Weak CSP) — PR #32.
- **Баннер частичного скана** — PR #33; **персистентность partial в историю** — PR #35.
- **Новые проверки:** Path Traversal/LFI (CWE-22), Open Redirect (CWE-601),
  Insecure Cookie Flags (CWE-614/1004), Stored XSS (CWE-79), JWT Expiration Not Verified (CWE-613) — PR #34;
  security.txt (RFC 9116, CWE-1059) — PR #35; JWT Weak Secret (CWE-326/347) — PR #36.
- **CLI-сканер** ```python scripts/cli.py --url … --fail-on high``` с exit-code гейтом — PR #34.
- **Discovery без OpenAPI** — robots.txt / sitemap.xml / common-paths — PR #34.
- **Per-check квоты бюджета** — SQLi/SSRF больше не съедают весь бюджет раньше остальных — PR #37.
- **Статистика покрытия в отчёте** — эндпоинты/поверхности/запросы в HTML/PDF-отчётах — PR #38.
- **Webhook-уведомления** — JSON-сводка по завершении скана (httpx, таймаут, 1 retry) — PR #39.
- **Supply-chain** — Docker base-image по digest, ```pip --require-hashes``` (hash-locked requirements) — PR #40.
- **Генерация about.html** — секция проверок из CHECK_METADATA + descriptions.py (gen_about.py --check в CI) — PR #41.

## Осталось

### Auth-профили
- Form-login, cookie-сессии, API-key header, refresh токена; сохранение профилей сканирования.

### Операционные фичи
- Расписание / повторные сканы.
- Проекты / мульти-цели, тренд-график по истории.
- i18n (EN-toggle) — опционально, проект RU-first.

