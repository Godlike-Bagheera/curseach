"""
DevSecOps Scanner — пакет веб-приложения.

Структура:
- scanner/config.py    — настройки из env, учётные данные, константы
- scanner/security.py  — сессии, rate-limit, SSRF/Origin-валидация
- scanner/tasks.py     — ScanTask, движок сканирования, фоновый GC
- scanner/reporting.py — рендер отчётов, SARIF, ZIP (без Playwright)
- scanner/routes/      — роутеры FastAPI по доменам
- scanner/app.py       — сборка приложения (FastAPI instance)

web_app.py оставлен как тонкий shim для обратной совместимости
(start.py, тесты, Dockerfile используют "web_app:app").
"""
