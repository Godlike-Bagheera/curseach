# Как контрибьютить

## Окружение

```bash
pip install -r requirements-dev.txt
pip install playwright==1.65.2          # для PDF (не в requirements.txt — см. Dockerfile)
python -m playwright install chromium   # один раз, ~150 МБ
python start.py                          # поднимет цель + сканер
```

Без Chromium сканер запустится, но PDF-экспорт будет недоступен.
Остальные отчёты (HTML/CSV/XLSX/JSON/SARIF/ZIP) работают.

## Гейты (как в CI)

```bash
ruff check .
ruff format --check .      # ruff 0.17.5 склеивает короткие конкатенации — форматьте перед пушем
mypy checks scanner/security.py
node --check static/*.js
pytest -q --cov=checks --cov=scanner --cov-fail-under=75
```

## Процесс

1. Ветка от `main`: `git checkout -b fix/краткое-описание`.
2. Коммиты с понятными сообщениями; не коммитьте токены/секреты.
3. PR в `main`; дождитесь зелёного CI (test 3.12/3.13, ui-smoke, self-scan).
4. Тесты не ослаблять; исправляя поведение — обновляйте/добавляйте тесты.

## Стиль

- Русские подписи в UI, простые формулировки для новичков.
- Тёмная CRT-тема, JetBrains Mono self-hosted; inline-`<script>` запрещён CSP (JS только в `/static`).
- Единый источник текстов/классификации — `checks/descriptions.py` (`get_vuln_info`).
- Коды CWE/OWASP и их маппинги — канон, не менять без согласования.
