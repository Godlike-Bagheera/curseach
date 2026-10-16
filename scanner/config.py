"""Настройки приложения: env, учётные данные сканера, константы."""

import hashlib
import os
import secrets
from urllib.parse import urlparse

# ---------- Настройки автологина в целевой API ----------
LOGIN_PATH = "/api/auth/login"
LOGIN_TOKEN_FIELD = "token"

# ---------- Учётные данные сканера (admin/guest) ----------
_SALT = b"devsecops_static_salt_v1"
_KDF_ITERATIONS = 100_000

ADMIN_USER = "admin"
GUEST_USER = "guest"


def _hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _SALT, _KDF_ITERATIONS
    ).hex()


ADMIN_PASSWORD_HASH = _hash_password("admin")
GUEST_PASSWORD_HASH = _hash_password("guest")


def authenticate(username: str, password: str):
    provided = _hash_password(password)
    if secrets.compare_digest(username.encode(), ADMIN_USER.encode()) and \
       secrets.compare_digest(provided, ADMIN_PASSWORD_HASH):
        return "admin"
    if secrets.compare_digest(username.encode(), GUEST_USER.encode()) and \
       secrets.compare_digest(provided, GUEST_PASSWORD_HASH):
        return "guest"
    return None


# ---------- Сессии / задачи ----------
SESSION_TTL_SECONDS = 8 * 60 * 60
TASK_TTL_SECONDS = 60 * 60
GC_INTERVAL_SECONDS = 5 * 60

QUEUE_MAXSIZE = 1000
MAX_LOG_LINES = 5000
LOG_TRIM_CHUNK = 1000


# ---------- Разрешённые origins (настраивается через env) ----------
# По умолчанию — локальные хосты; для публичного деплоя добавьте свой домен:
#   ALLOWED_HOSTS="scanner.example.com,myapp.github.io"
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get(
        "ALLOWED_HOSTS",
        "127.0.0.1,localhost,::1,*.github.dev,*.githubcodespaces.app,"
        "*.preview.app.github.dev",
    ).split(",")
    if h.strip()
}


def origin_allowed(origin: str) -> bool:
    if not origin:
        return True
    try:
        p = urlparse(origin)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if host in ALLOWED_HOSTS:
        return True
    # wildcard-записи вида *.example.com
    for pattern in ALLOWED_HOSTS:
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            if host.endswith(suffix) or host == pattern[2:]:
                return True
    return False


# ---------- SSRF ----------
SSRF_ALLOW_PRIVATE = os.environ.get("SCANNER_ALLOW_PRIVATE_TARGETS", "1") == "1"

# ---------- Rate limiting логина ----------
LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "10"))


def calculate_score(critical: int, high: int, medium: int, low: int) -> int:
    penalty = critical * 20 + high * 10 + medium * 5 + low * 2
    return max(0, 100 - penalty)


MODE_TITLES_RU = {
    "quick": "БЫСТРОЕ СКАНИРОВАНИЕ",
    "full": "ПОЛНОЕ СКАНИРОВАНИЕ",
    "custom": "ВЫБОРОЧНОЕ СКАНИРОВАНИЕ",
}

MODE_TITLES_REPORT = {
    "quick": "БЫСТРАЯ ПРОВЕРКА",
    "full": "ПОЛНАЯ ПРОВЕРКА",
    "custom": "ВЫБОРОЧНАЯ ПРОВЕРКА",
}

LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
