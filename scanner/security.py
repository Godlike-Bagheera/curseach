"""Сессии, CSRF/Origin-политика, SSRF-валидация, rate-limit логина."""

import ipaddress
import re
import secrets
import socket
import time
from urllib.parse import urlparse

import httpx
from fastapi import Cookie, HTTPException

from .config import (
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    SCAN_PIN_DNS,
    SESSION_TTL_SECONDS,
    SSRF_ALLOW_PRIVATE,
    authenticate,
    origin_allowed,
)

# ---------- Сессии ----------
sessions: dict[str, tuple[str, float]] = {}


def create_session(username: str) -> str:
    sid = secrets.token_urlsafe(32)
    sessions[sid] = (username, time.time())
    return sid


def destroy_session(sid: str | None) -> None:
    if sid and sid in sessions:
        sessions.pop(sid, None)


def get_current_user(session_id: str | None = Cookie(None)) -> str | None:
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


def require_user(session_id: str | None = Cookie(None)) -> str:
    user = get_current_user(session_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(session_id: str | None = Cookie(None)) -> str:
    user = require_user(session_id)
    if user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ---------- SSRF-защита: блокировка private/loopback/link-local ----------
_ALWAYS_BLOCKED_NETS = [
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # IPv6 metadata
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
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast


def ssrf_check_host(host: str) -> str | None:
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


def validate_target_url(url: str) -> str | None:
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
_login_attempts: dict[str, list[float]] = {}


def check_login_rate(client_ip: str) -> bool:
    """True — запрос разрешён; False — лимит превышен."""
    now = time.time()
    bucket = _login_attempts.setdefault(client_ip, [])
    bucket[:] = [t for t in bucket if now - t < LOGIN_WINDOW_SECONDS]
    if len(bucket) >= LOGIN_MAX_ATTEMPTS:
        return False
    bucket.append(now)
    return True


# ---------- Anti-DNS-rebinding: пиннинг проверенного IP ----------
def resolve_target_ip(host: str) -> str | None:
    """
    Возвращает проверенный (не запрещённый SSRF-политикой) IP для хоста.
    Если host — уже IP-литерал, возвращает его как есть.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return None
    for info in infos:
        ip = info[4][0]
        if not _is_blocked_ip(ip):
            return ip
    return None


def _pin_request(request: httpx.Request, host: str, ip: str) -> httpx.Request:
    """Подменяет хост на проверенный IP, сохраняя Host-заголовок и SNI."""
    host_header = request.headers.get("host", host)
    raw = [(k, v) for k, v in request.headers.raw if k.lower() != b"host"]
    raw.append((b"host", host_header.encode("utf-8")))
    extensions = dict(request.extensions)
    extensions["sni_hostname"] = host
    return httpx.Request(
        request.method,
        request.url.copy_with(host=ip),
        headers=raw,
        content=request.content,
        extensions=extensions,
    )


class PinnedTransport(httpx.AsyncHTTPTransport):
    """
    Транспорт, пиннящий проверенный IP: DNS резолвится один раз при
    валидации цели, все соединения идут на этот IP (Host/SNI сохраняются).
    Закрывает TOCTOU/DNS-rebinding между SSRF-проверкой и запросом.
    """

    def __init__(self, host: str, ip: str, **kwargs):
        super().__init__(**kwargs)
        self._pin_host = host
        self._pin_ip = ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == self._pin_host and self._pin_host != self._pin_ip:
            await request.aread()
            request = _pin_request(request, self._pin_host, self._pin_ip)
        return await super().handle_async_request(request)


def pinned_client_kwargs(target_url: str) -> dict:
    """kwargs для httpx.AsyncClient с пиннингом IP (если включён SCAN_PIN_DNS)."""
    if not SCAN_PIN_DNS:
        return {}
    try:
        host = urlparse(target_url).hostname
    except ValueError:
        return {}
    if not host:
        return {}
    ip = resolve_target_ip(host)
    if ip and ip != host:
        return {"transport": PinnedTransport(host, ip)}
    return {}


__all__ = [
    "authenticate",
    "origin_allowed",
    "sessions",
    "create_session",
    "destroy_session",
    "get_current_user",
    "require_user",
    "require_admin",
    "ssrf_check_host",
    "validate_target_url",
    "safe_host_for_filename",
    "check_login_rate",
    "resolve_target_ip",
    "PinnedTransport",
    "pinned_client_kwargs",
]
