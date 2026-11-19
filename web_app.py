"""
Точка входа сканера (обратная совместимость).

Веб-приложение модульно разнесено по пакету scanner/:
- scanner/config.py    — настройки и учётные данные
- scanner/security.py  — сессии, SSRF, rate-limit
- scanner/tasks.py     — ScanTask и движок сканирования
- scanner/reporting.py — отчёты, SARIF, ZIP
- scanner/routes/*     — HTTP-роуты
- scanner/app.py       — сборка FastAPI

Здесь только реэкспорт: `uvicorn web_app:app` (start.py, Dockerfile, CI)
и тесты (`import web_app`) продолжают работать без изменений.
"""

from scanner.app import app  # noqa: F401  (uvicorn web_app:app)
from scanner.config import (  # noqa: F401
    ADMIN_PASSWORD_HASH,
    GUEST_PASSWORD_HASH,
    LOGIN_PATH,
    LOGIN_TOKEN_FIELD,
    MODE_TITLES_REPORT,
    SESSION_TTL_SECONDS,
    calculate_score,
)
from scanner.reporting import (  # noqa: F401
    build_chart_context as _build_chart_context,
)
from scanner.security import (  # noqa: F401
    authenticate,
    create_session,
    destroy_session,
    get_current_user,
    require_admin,
    require_user,
    sessions,
)
from scanner.tasks import (  # noqa: F401
    AccountConfig,
    ScanRequest,
    ScanTask,
    run_scan_in_thread,
    scan_engine,
    tasks,
)

if __name__ == "__main__":
    from scanner.app import _run_server

    _run_server()
