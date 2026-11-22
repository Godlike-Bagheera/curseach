import os
import tempfile

import pytest

# Тестовая БД в отдельном файле, чтобы не трогать scans.db
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["SCANNER_DB_PATH"] = _tmp.name
# Тесты гоняют сканы локально — RPS-лимит не нужен, таймаут побольше.
os.environ.setdefault("SCAN_RPS", "0")
os.environ.setdefault("SCAN_TOTAL_TIMEOUT", "180")


@pytest.fixture(autouse=True)
def _reset_auth_state():
    """Изоляция тестов: глобальные сессии и rate-limit логина не протекают между тестами."""
    from scanner import security

    security._login_attempts.clear()
    security.sessions.clear()
    yield
    security._login_attempts.clear()
    security.sessions.clear()
