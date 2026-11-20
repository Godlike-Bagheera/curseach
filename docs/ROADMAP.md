# Roadmap: оставшиеся улучшения

Уже сделано (PR #31, #32, #33): точность детектирования (A), hardening сканера (B),
учебная цель покрывает почти все проверки (C), качество/CI/доки/a11y (E/F),
CORS reflection + качество CSP (D-bounded), баннер частичного скана.

## Новые проверки (D)

- **Path Traversal / LFI** — probing параметров путевыми payload (`../../etc/passwd`,
  `..%2f..%2f`) с сигнатурами ответов; отдельный тип + CWE-22.
- **Insecure Cookie Flags** — анализ `Set-Cookie` (Secure/HttpOnly/SameSite); CWE-614/1004.
- **Open Redirect** — параметры `redirect/next/url` с внешним Location; CWE-601.
- **JWT exp / weak-secret** — истёкшие токены, подбор слабого HMAC-секрета (wordlist).
- **Stored XSS** — POST payload → GET списка, проверка отражения.
- **security.txt / CSP report-only** — информационные проверки.

Каждая: описание в `descriptions.py`, `CHECK_METADATA`, `CHECK_VULN`, тесты
(MockTransport) + эндпоинт учебной цели для демонстрации.

## Бюджет и покрытие (D)

- Per-check квоты бюджета (сейчас first-come-first-served: SQLi/SSRF съедают бюджет).
- Статистика покрытия в отчёте: поверхностей протестировано N из M.

## Discovery без OpenAPI (D)

- Fallback: robots.txt, sitemap.xml, crawl ссылок, common-paths — когда спеки нет.

## Auth-профили (D)

- Form-login, cookie-сессии, API-key header, refresh токена; сохранение профилей.

## Операционные фичи (D)

- CLI-режим с exit-code гейтом (`curseach scan --url … --fail-on high`).
- Расписание / повторные сканы, webhook-уведомления.
- Проекты / мульти-цели, тренд-график по истории.
- i18n (EN-toggle) — опционально, проект RU-first.

## Прочее

- Персистентность `partial` в историю (колонка БД) — сейчас баннер только для активного скана.
- Генерация `about.html` из единого источника проверок.
- Пиннинг base-image Docker по digest, `pip --require-hashes`.
