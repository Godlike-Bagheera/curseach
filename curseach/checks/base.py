"""Общие обёртки над httpx, контекст скана и утилиты."""

import hashlib
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class ScanContext:
    """
    Контекст одного скана.

    client             — основной HTTP-клиент (с авторизацией user1, если задана;
                         иначе — анонимный).
    anon_client        — всегда анонимный. Нужен для сравнения «авторизован / нет».
    secondary_client   — клиент с авторизацией user2 (если задана). Нужен для
                         cross-user IDOR/BOLA.
    has_auth           — True, если задан основной auth.
    has_auth_secondary — True, если задан второй auth.
    """
    target_url: str
    client: httpx.AsyncClient
    anon_client: httpx.AsyncClient
    has_auth: bool = False
    secondary_client: Optional[httpx.AsyncClient] = None
    has_auth_secondary: bool = False


async def _safe_request(
    client: httpx.AsyncClient, method: str, url: str, **kwargs
) -> Optional[httpx.Response]:
    try:
        return await client.request(method, url, **kwargs)
    except httpx.HTTPError:
        return None
    except (ValueError, UnicodeError):
        return None


async def _safe_get(client, url, **kw) -> Optional[httpx.Response]:
    return await _safe_request(client, "GET", url, **kw)


async def _safe_post(client, url, **kw) -> Optional[httpx.Response]:
    return await _safe_request(client, "POST", url, **kw)


async def _safe_options(client, url, **kw) -> Optional[httpx.Response]:
    return await _safe_request(client, "OPTIONS", url, **kw)


def _body(resp: Optional[httpx.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text.lower()
    except (UnicodeDecodeError, LookupError):
        return ""


def _content_hash(resp: Optional[httpx.Response]) -> str:
    if resp is None:
        return ""
    try:
        return hashlib.md5(resp.content).hexdigest()
    except Exception:
        return ""


def _method_not_supported(resp: Optional[httpx.Response]) -> bool:
    if resp is None:
        return True
    return resp.status_code in (404, 405, 501)


def _build_path(ep: str, param_name: str, payload: str) -> str:
    encoded = urllib.parse.quote(payload, safe='')
    return ep.replace(f"{{{param_name}}}", encoded)


# ---------- Фильтр «это эндпоинт аутентификации?» ----------
# На такие эндпоинты нельзя навешивать CSRF-проверки, mass-assignment
# и content-type-валидацию: логин по определению принимает произвольный
# ввод без CSRF-токена и не является state-changing операцией,
# требующей CSRF-защиты.
_AUTH_PATH_MARKERS = (
    "/auth", "/login", "/logout",
    "/signin", "/signup", "/register",
)


def _is_auth_endpoint(path: str) -> bool:
    """True, если путь относится к аутентификации / регистрации."""
    p = (path or "").lower()
    return any(m in p for m in _AUTH_PATH_MARKERS)


SQL_ERROR_PATTERNS = [
    "sqlite3", "sqlite error", "syntax error", "unrecognized token",
    "sql syntax", "mysql", "postgresql", "psql", "pg_query",
    "ora-", "oracle", "unclosed quotation mark", "unterminated string",
    "sqlstate", "you have an error in your sql", "warning: mysql",
    "odbc", "jdbc",
]