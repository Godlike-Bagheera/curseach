"""Общие обёртки над httpx, контекст скана и утилиты."""

import asyncio
import contextvars
import hashlib
import json as _json
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import httpx

from .descriptions import get_vuln_info


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
    secondary_client: httpx.AsyncClient | None = None
    has_auth_secondary: bool = False
    openapi: dict | None = None
    # Инфраструктура скана (заполняется движком; в юнит-тестах может быть None):
    semaphore: asyncio.Semaphore | None = None  # лимит одновременных запросов
    budget: Optional["RequestBudget"] = None  # общий бюджет запросов на скан
    limiter: Optional["RateLimiter"] = None  # RPS-лимит («вежливое» сканирование)
    cancel_event: threading.Event | None = None  # кооперативная отмена скана
    scan_seed: int | None = None  # детерминированный профиль цели


class ScanCancelled(Exception):
    """Скан отменён пользователем (кооперативная отмена через cancel_event)."""


class RequestBudget:
    """Общий бюджет HTTP-запросов на один скан (защита от «долбёжки» цели)."""

    def __init__(self, max_requests: int):
        self.max_requests = max(1, int(max_requests))
        self.used = 0
        self.exhausted = False

    def take(self, n: int = 1) -> bool:
        if self.used + n > self.max_requests:
            self.exhausted = True
            return False
        self.used += n
        return True


class RateLimiter:
    """Простейший интервальный RPS-лимит (asyncio, один event loop)."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def wait(self):
        if self.min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next_slot - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            self._next_slot = now + self.min_interval


# Контекст текущего скана и лог evidence — изолированы по asyncio-задачам
# (каждая проверка выполняется в своей task через ContextVar).
_SCAN_CTX: contextvars.ContextVar = contextvars.ContextVar("scan_ctx", default=None)
_EVIDENCE_LOG: contextvars.ContextVar = contextvars.ContextVar("evidence_log", default=None)


_SENSITIVE_JSON_RE = re.compile(
    r'("(?:password|passwd|pwd|secret|token|api_?key|authorization|access_?token|refresh_?token|client_?secret)"\s*:\s*")[^"]*(")',
    re.IGNORECASE,
)
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+")


def _redact_text(text: str | None) -> str | None:
    """Маскирует секреты в evidence (пароли/токены/ключи) перед сохранением и экспортом."""
    if not text:
        return text
    text = _SENSITIVE_JSON_RE.sub(r"\1***\2", text)
    text = _PEM_RE.sub("***PRIVATE KEY***", text)
    text = _AWS_KEY_RE.sub("***AWS KEY***", text)
    text = _BEARER_RE.sub(r"\1***", text)
    return text


def redact_evidence(evd: dict | None) -> dict | None:
    if not isinstance(evd, dict):
        return evd
    out = dict(evd)
    if out.get("request_body"):
        out["request_body"] = _redact_text(out["request_body"])
    if out.get("response_body"):
        out["response_body"] = _redact_text(out["response_body"])
    return out


def _make_evidence(method: str, url: str, kwargs: dict, r: httpx.Response, elapsed_ms: int) -> dict:
    req_body = None
    if kwargs.get("json") is not None:
        try:
            req_body = _json.dumps(kwargs["json"], ensure_ascii=False)[:400]
        except (TypeError, ValueError):
            req_body = str(kwargs["json"])[:400]
    elif kwargs.get("content") is not None:
        c = kwargs["content"]
        req_body = (c.decode("utf-8", "replace") if isinstance(c, bytes) else str(c))[:400]
    try:
        resp_body = r.text[:800]
    except (UnicodeDecodeError, LookupError):
        resp_body = "<binary>"
    return {
        "method": method.upper(),
        "url": str(url),
        "request_body": _redact_text(req_body),
        "status": r.status_code,
        "content_type": r.headers.get("content-type", ""),
        "response_body": _redact_text(resp_body),
        "elapsed_ms": elapsed_ms,
    }


async def _do_request(client, method: str, url: str, kwargs: dict) -> httpx.Response | None:
    t0 = time.perf_counter()
    try:
        r = await client.request(method, url, **kwargs)
    except (httpx.HTTPError, ValueError, UnicodeError):
        return None
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    try:
        evd = _make_evidence(method, url, kwargs, r, elapsed_ms)
        r.evidence = evd
        log = _EVIDENCE_LOG.get(None)
        if log is not None:
            log.append(evd)
    except Exception:
        pass
    return r


async def _safe_request(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
    """
    Единая точка всех запросов проверок: семафор, бюджет, RPS-лимит,
    отмена и сбор evidence. Вне движка (юнит-тесты) работает как раньше.
    """
    ctx = _SCAN_CTX.get(None)
    sem = None
    if ctx is not None:
        if ctx.cancel_event is not None and ctx.cancel_event.is_set():
            raise ScanCancelled()
        if ctx.budget is not None and not ctx.budget.take():
            return None
        if ctx.limiter is not None:
            await ctx.limiter.wait()
        sem = ctx.semaphore
    if sem is not None:
        async with sem:
            return await _do_request(client, method, url, kwargs)
    return await _do_request(client, method, url, kwargs)


def ev(r: httpx.Response | None) -> dict | None:
    """Evidence, прикреплённый к ответу (если запрос шёл через _safe_request)."""
    return getattr(r, "evidence", None)


async def _safe_get(client, url, **kw) -> httpx.Response | None:
    return await _safe_request(client, "GET", url, **kw)


async def _safe_post(client, url, **kw) -> httpx.Response | None:
    return await _safe_request(client, "POST", url, **kw)


async def _safe_options(client, url, **kw) -> httpx.Response | None:
    return await _safe_request(client, "OPTIONS", url, **kw)


def _body(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        return resp.text.lower()
    except (UnicodeDecodeError, LookupError):
        return ""


def _content_hash(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        return hashlib.md5(resp.content).hexdigest()
    except Exception:
        return ""


def _norm_body(r) -> str:
    """Нормализует динамику (timestamps/UUID/nonce) перед хеш-сравнением."""
    try:
        text = r.text
    except (UnicodeDecodeError, LookupError):
        return ""
    text = re.sub(r"\b\d{10,13}\b", "<TS>", text)
    text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>", text)
    text = re.sub(
        r'"(timestamp|ts|time|date|nonce|request_id|trace_id|expires?)"\s*:\s*("[^"]*"|\d+)',
        r'"\1":<DYN>',
        text,
        flags=re.IGNORECASE,
    )
    return text.lower()


def _norm_hash(r) -> str:
    """Хеш нормализованного тела — для сравнения ответов с динамикой."""
    return hashlib.md5(_norm_body(r).encode("utf-8", "replace")).hexdigest()


def _method_not_supported(resp: httpx.Response | None) -> bool:
    if resp is None:
        return True
    return resp.status_code in (404, 405, 501)


def _build_path(ep: str, param_name: str, payload: str) -> str:
    encoded = urllib.parse.quote(payload, safe="")
    return ep.replace(f"{{{param_name}}}", encoded)


# ---------- Фильтр «это эндпоинт аутентификации?» ----------
# На такие эндпоинты нельзя навешивать CSRF-проверки, mass-assignment
# и content-type-валидацию: логин по определению принимает произвольный
# ввод без CSRF-токена и не является state-changing операцией,
# требующей CSRF-защиты.
_AUTH_SEGMENTS = {"auth", "login", "logout", "signin", "signup", "register", "oauth", "token"}


def _is_auth_endpoint(path: str) -> bool:
    """True, если путь относится к аутентификации / регистрации (по сегментам, не подстроке)."""
    segments = {s for s in (path or "").lower().split("/") if s}
    return bool(segments & _AUTH_SEGMENTS)


SQL_ERROR_PATTERNS = [
    "sqlite3",
    "sqlite error",
    "syntax error",
    "unrecognized token",
    "sql syntax",
    "mysql",
    "postgresql",
    "psql",
    "pg_query",
    "ora-",
    "oracle",
    "unclosed quotation mark",
    "unterminated string",
    "sqlstate",
    "you have an error in your sql",
    "warning: mysql",
    "odbc",
    "jdbc",
]

# ---------- Хелперы по OpenAPI-спеке ----------
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
_PUBLIC_PATHS = {"/", "/docs", "/redoc", "/openapi.json", "/favicon.ico", "/health", "/healthz", "/robots.txt"}


def _spec_paths(ctx: "ScanContext") -> dict:
    spec = ctx.openapi or {}
    paths = spec.get("paths")
    return paths if isinstance(paths, dict) else {}


def _path_methods(ctx: "ScanContext", ep: str) -> set:
    ops = _spec_paths(ctx).get(ep)
    if not isinstance(ops, dict):
        return set()
    return {k.lower() for k in ops if k.lower() in _HTTP_METHODS}


def _writable_endpoints(ctx: "ScanContext", endpoints: list[str]) -> list[str]:
    """Статические не-auth эндпоинты, реально принимающие POST/PUT/PATCH (по спеке)."""
    out = []
    for e in endpoints:
        if "{" in e or "}" in e or not e.startswith("/") or _is_auth_endpoint(e):
            continue
        methods = _path_methods(ctx, e)
        if methods and not (methods & {"post", "put", "patch"}):
            continue
        out.append(e)
    return out


def _endpoint_requires_security(ctx: "ScanContext", ep: str) -> bool:
    ops = _spec_paths(ctx).get(ep)
    if not isinstance(ops, dict):
        return False
    return any(isinstance(op, dict) and op.get("security") for op in ops.values())


def _endpoint_explicitly_public(ctx: "ScanContext", ep: str) -> bool:
    spec = ctx.openapi or {}
    has_schemes = bool((spec.get("components") or {}).get("securitySchemes")) or bool(spec.get("security"))
    if not has_schemes:
        return False
    ops = _spec_paths(ctx).get(ep)
    if not isinstance(ops, dict):
        return False
    return any(isinstance(op, dict) and op.get("security") == [] for op in ops.values())


# ---------- Классификация / дедупликация / evidence ----------
_LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def default_confidence(f: dict) -> str:
    meta = get_vuln_info(f.get("type", "")) or {}
    return meta.get("confidence", "medium")


def _template_regex(ep: str):
    parts = re.split(r"\{[^}]+\}", ep)
    return re.compile("^" + "[^/]+".join(re.escape(p) for p in parts) + "$")


def pick_evidence(log: list[dict] | None, endpoint: str) -> dict | None:
    """Последний (самый релевантный) запрос к эндпоинту из лога проверки."""
    if not log or not endpoint:
        return None
    rx = _template_regex(endpoint)
    best = None
    for e in log:
        try:
            path = urllib.parse.urlparse(e.get("url", "")).path
        except (ValueError, AttributeError):
            continue
        if path == endpoint or rx.match(path):
            best = e
    return best


def enrich_findings(findings: list[dict], log: list[dict] | None = None) -> list[dict]:
    """Проставляет confidence по умолчанию и evidence из лога запросов."""
    for f in findings:
        f.setdefault("method", "")
        f.setdefault("param", "")
        if not f.get("confidence"):
            f["confidence"] = default_confidence(f)
        if not f.get("evidence") and log:
            picked = pick_evidence(log, f.get("endpoint", ""))
            if picked:
                f["evidence"] = picked
        if f.get("evidence"):
            f["evidence"] = redact_evidence(f["evidence"])
    return findings


def dedup_findings(findings: list[dict]) -> list[dict]:
    """
    Дедуп по (type, endpoint, param, method): IDOR ловится несколькими
    проверками — в отчёте должна остаться одна, самая серьёзная/уверенная.
    """
    best: dict = {}
    for f in findings:
        key = (
            f.get("type", ""),
            f.get("endpoint", ""),
            f.get("param", "") or "",
            f.get("method", "") or "",
        )
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue

        def rank(x):
            return (
                _LEVEL_RANK.get(x.get("level", "LOW"), 9),
                _CONF_RANK.get(x.get("confidence", "medium"), 1),
            )

        if rank(f) < rank(cur):
            best[key] = f
    out = list(best.values())
    out.sort(key=lambda x: (_LEVEL_RANK.get(x.get("level", "LOW"), 9), x.get("type", ""), x.get("endpoint", "")))
    return out
