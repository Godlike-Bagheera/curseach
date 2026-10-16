"""Сессии, CSRF/Origin-политика, SSRF-валидация, rate-limit логина."""

import ipaddress
import re
import secrets
import socket
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Cookie, HTTPException

from .config import (
    SESSION_TTL_SECONDS,
    SSRF_ALLOW_PRIVATE,
    LOGIN_WINDOW_SECONDS,
    LOGIN_MAX_ATTEMPTS,
    authenticate,
    origin_allowed,
)

# ---------- Сессии ----------
sessions: Dict[str, Tuple[str, float]] = {}


def create_session(username: str) -> str:
    sid = secrets.token_urlsafe(32)
    sessions[sid] = (username, time.time())
    return sid


def destroy_session(sid: Optional[str]) -> None:
    if sid and sid in sessions:
        sessions.pop(sid, None)


def get_current_user(session_id: Optional[str] = Cookie(None)) -> Optional[str]:
    if not session_id:
        return None
    entry = sessions.get(session_id)
    if not entry:
        return None
    username, created_at = entry
    if time.time() - created_at > SESSION_TTL_SECONDS:
        sessions.pop(session_id, None)
        return None
    sessions[session_id] = (username, time.time())
    return username


def require_user(session_id: Optional[str] = Cookie(None)) -> str:
    user = get_current_user(session_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(session_id: Optional[str] = Cookie(None)) -> str:
    user = require_user(session_id)
    if user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ---------- SSRF-защита: блокировка private/loopback/link-local ----------
_ALWAYS_BLOCKED_NETS = [
    ipaddress.ip_network("169.254.169.254/32"),   # AWS/GCP metadata
    ipaddress.ip_network("fd00:ec2::254/128"),    # IPv6 metadata
]


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _ALWAYS_BLOCKED_NETS:
        if addr in net:
            return True
    if SSRF_ALLOW_PRIVATE:
        return False
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast
    )


def ssrf_check_host(host: str) -> Optional[str]:
    """Возвращает сообщение об ошибке, если хост запрещён."""
    # Прямой IP?
    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            return f"Запрещённый целевой адрес (SSRF protection): {host}"
        return None
    except ValueError:
        pass
    # Decimal/octal/hex обфускация вида http://2130706433
    if host.isdigit():
        try:
            if _is_blocked_ip(str(ipaddress.IPv4Address(int(host)))):
                return f"Запрещённый целевой адрес (обфускация IP): {host}"
        except ValueError:
            pass
    # DNS-резолвинг: проверяем ВСЕ адреса, на которые указывает хост
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return None  # не резолвится — пусть дальше упадёт сам запрос
    seen = set()
    for info in infos:
        ip = info[4][0]
        if ip in seen:
            continue
        seen.add(ip)
        if _is_blocked_ip(ip):
            return f"Хост {host} резолвится в запрещённый адрес {ip} (SSRF protection)"
    return None


def validate_target_url(url: str) -> Optional[str]:
    """
    Проверяет URL. Использует urlparse вместо ручного split — так
    корректно обрабатываются IPv6-адреса вида http://[::1]:8000,
    user:pass@host и прочие нестандартные формы.
    """
    if not url:
        return "URL не задан"
    if not isinstance(url, str):
        return "URL должен быть строкой"

    url = url.strip()
    if not url:
        return "URL не задан"

    if not (url.startswith("http://") or url.startswith("https://")):
        return "URL должен начинаться с http:// или https://"

    if any(c in url for c in (" ", "\t", "\n", "\r", '"', "'", "<", ">")):
        return "URL содержит недопустимые символы"

    try:
        parsed = urlparse(url)
    except Exception:
        return "Не удалось разобрать URL"

    host = parsed.hostname
    if not host:
        return "URL не содержит хост"

    host_lower = host.lower()

    # urlparse возвращает hostname для IPv6 БЕЗ квадратных скобок,
    # например '::1' — поэтому ':' в hostname = это IPv6.
    if ":" in host_lower:
        return ssrf_check_host(host_lower)  # None => OK

    # SSRF-защита: проверяем IP и DNS-резолвинг хоста.
    ssrf_err = ssrf_check_host(host_lower)
    if ssrf_err:
        return ssrf_err

    allowed_plain = ("localhost", "127.0.0.1")
    if "." not in host_lower and host_lower not in allowed_plain:
        return f"Некорректный хост: {host}"

    return None


def safe_host_for_filename(target_url: str) -> str:
    try:
        parsed = urlparse(target_url)
        host = parsed.netloc or parsed.hostname or "target"
    except Exception:
        host = "target"
    host = re.sub(r"[^A-Za-z0-9._\-]", "-", host)
    host = host.strip("-") or "target"
    return host


# ---------- Rate limiting логина (защита от брутфорса) ----------
_login_attempts: Dict[str, List[float]] = {}


def check_login_rate(client_ip: str) -> bool:
    """True — запрос разрешён; False — лимит превышен."""
    now = time.time()
    bucket = _login_attempts.setdefault(client_ip, [])
    bucket[:] = [t for t in bucket if now - t < LOGIN_WINDOW_SECONDS]
    if len(bucket) >= LOGIN_MAX_ATTEMPTS:
        return False
    bucket.append(now)
    return True


__all__ = [
    "authenticate", "origin_allowed",
    "sessions", "create_session", "destroy_session",
    "get_current_user", "require_user", "require_admin",
    "ssrf_check_host", "validate_target_url", "safe_host_for_filename",
    "check_login_rate",
]
