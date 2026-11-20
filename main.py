"""
Damn Vulnerable API — учебная цель для сканера DevSecOps.

Рандомизация выполняется на уровне "скана" (серии запросов).
Сканер в начале каждого скана дёргает /openapi.json с заголовком
X-Scan-Start: 1 — по этому запросу генерируется новый профиль уязвимостей.
Все последующие запросы в рамках одного скана используют этот же профиль,
а между сканами они существенно отличаются.

Обычные запросы к /openapi.json (например, от Swagger UI) профиль НЕ сбрасывают.

Реализованные уязвимости:
- SQLi в /api/users/{user_id}
- BOLA / IDOR в /api/orders/{order_id} — доступ к чужому заказу
- BFLA в /api/admin/users — обычный user видит админский список
- Sensitive data leak в /api/system/keys
- Business logic error (отрицательные ID)
- Утечка ошибок СУБД
- Рандомизация заголовков безопасности
"""

import os
import random
import sqlite3
import time
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel

app = FastAPI(title="Damn Vulnerable API", version="1.0")

# УЯЗВИМОСТЬ: Open CORS — разрешаем любые источники (ловится check_cors).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Тестовая БД в памяти ----------
conn = sqlite3.connect("file::memory:?cache=shared", uri=True, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")
cursor.execute("INSERT INTO users VALUES (1, 'alice', 'alice_secret_777')")
cursor.execute("INSERT INTO users VALUES (2, 'bob', 'bob_secret_123')")
cursor.execute("INSERT INTO users VALUES (3, 'admin', 'admin_hash_777')")
conn.commit()
# Первичный курсор больше не нужен — работаем новыми на каждый запрос.
cursor.close()


# ---------- Пользователи, токены, заказы ----------
_USERS = {
    1: {"username": "alice", "password": "alice123", "role": "user"},
    2: {"username": "bob", "password": "bob123", "role": "user"},
    3: {"username": "admin", "password": "admin123", "role": "admin"},
}

# Простая схема: токен = фиксированная строка, привязанная к user_id.
# В реальной жизни был бы JWT/HMAC; здесь — для учебной цели.
_TOKENS = {
    "token_alice_aaa111": 1,
    "token_bob_bbb222": 2,
    "token_admin_ccc333": 3,
}

# Заказы: id -> {user_id, item, price}
_ORDERS = {
    1: {"id": 1, "user_id": 1, "item": "laptop", "price": 1200},
    2: {"id": 2, "user_id": 1, "item": "mouse", "price": 25},
    3: {"id": 3, "user_id": 2, "item": "keyboard", "price": 80},
    4: {"id": 4, "user_id": 2, "item": "monitor", "price": 350},
    5: {"id": 5, "user_id": 3, "item": "server", "price": 5000},
}


def _resolve_token(authorization: str | None) -> int | None:
    """Возвращает user_id, если токен валиден, иначе None."""
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return _TOKENS.get(parts[1])


# ---------- Профиль скана ----------
_ALL_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
]

_HEADER_VALUES = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

_state = {
    "rng": random.Random(),
    "profile": {},
}


def _new_scan(seed: int | None = None):
    """
    Генерирует новый профиль уязвимостей для одного скана.
    С seed (заголовок X-Scan-Seed) профиль детерминирован — для
    воспроизводимых e2e-тестов и self-scan в CI.
    """
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random.Random(time.time_ns() ^ int.from_bytes(os.urandom(4), "big"))

    # Сколько заголовков ПРИСУТСТВУЕТ в этом скане (0-5)
    n_present = rng.choices(
        [0, 1, 2, 3, 4, 5],
        weights=[10, 15, 25, 25, 15, 10],
    )[0]
    headers_present = set(rng.sample(_ALL_HEADERS, n_present))

    _state["rng"] = rng
    _state["profile"] = {
        "headers_present": headers_present,
        "sqli_enabled": rng.random() < 0.80,
        "idor_enabled": rng.random() < 0.90,  # /api/system/keys без auth
        "order_idor_enabled": rng.random() < 0.80,  # /api/orders/{id}: без проверки владельца
        "bfla_enabled": rng.random() < 0.80,  # /api/admin/users: без проверки роли
        "sensitive_enabled": rng.random() < 0.75,
        "business_enabled": rng.random() < 0.75,
        "jwt_none_enabled": rng.random() < 0.80,  # /api/reports/{id}: JWT alg=none
        "global_bias": 1.0 if seed is not None else rng.uniform(0.7, 1.3),
        "seeded": seed is not None,
        "ssrf_enabled": rng.random() < 0.80,  # /api/fetch-url: без проверки URL
    }
    # Демо-режим «всё включено» (X-Scan-Seed: 0): все уязвимости активны,
    # заголовки безопасности отсутствуют — удобно показывать все проверки сразу.
    if seed == 0:
        for key in _state["profile"]:
            if key.endswith("_enabled"):
                _state["profile"][key] = True
        _state["profile"]["headers_present"] = set()
        _state["profile"]["seeded"] = True


_new_scan()  # инициализация при старте сервера


def _profile() -> dict:
    return _state["profile"]


def _maybe(prob: float) -> bool:
    """Бросок кубика с учётом глобального bias-а текущего скана."""
    bias = _state["profile"].get("global_bias", 1.0)
    adjusted = min(1.0, max(0.0, prob * bias))
    if _state["profile"].get("seeded"):
        # Детерминированный режим: результат не зависит от порядка запросов
        # (сканер ходит параллельно), высокие вероятности всегда срабатывают.
        return adjusted >= 0.5
    return _state["rng"].random() < adjusted


def _is_suspicious_input(value: str) -> bool:
    """Эвристика: содержит ли ввод SQL-подобные маркеры."""
    markers = ("'", '"', "--", ";", "UNION", "SELECT", "SLEEP", "WAITFOR", "PG_SLEEP", " OR ", " AND ")
    upper = value.upper()
    return any(m in upper for m in markers)


# ---------- Middleware ----------
@app.middleware("http")
async def randomized_middleware(request, call_next):
    # Новый скан стартует только по явному заголовку X-Scan-Start: 1.
    if request.url.path == "/openapi.json" and request.headers.get("x-scan-start") == "1":
        seed_hdr = request.headers.get("x-scan-seed", "")
        seed = int(seed_hdr) if seed_hdr.lstrip("-").isdigit() else None
        _new_scan(seed)

    response = await call_next(request)

    present = _state["profile"].get("headers_present", set())
    for name in present:
        response.headers[name] = _HEADER_VALUES[name]

    return response


# ---------- Модели ----------
class LoginRequest(BaseModel):
    username: str
    password: str


# ---------- Корневой роут ----------
@app.get("/")
def root():
    return {"status": "ok", "docs": "/docs"}


# ---------- Аутентификация ----------
@app.post("/api/auth/login")
def login(body: LoginRequest):
    """Логин. Возвращает токен (простой, фиксированный)."""
    for uid, info in _USERS.items():
        if info["username"] == body.username and info["password"] == body.password:
            for tok, token_uid in _TOKENS.items():
                if token_uid == uid:
                    return {"token": tok, "user_id": uid, "role": info["role"]}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ---------- Профиль текущего пользователя ----------
@app.get("/api/me")
def get_me(authorization: str = Header(None)):
    user_id = _resolve_token(authorization)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    info = _USERS[user_id]
    return {"user_id": user_id, "username": info["username"], "role": info["role"]}


@app.get("/api/me/orders")
def get_my_orders(authorization: str = Header(None)):
    """Возвращает заказы текущего пользователя."""
    user_id = _resolve_token(authorization)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    orders = [o for o in _ORDERS.values() if o["user_id"] == user_id]
    return {"data": orders}


# ---------- УЯЗВИМОСТЬ: IDOR в заказах ----------
@app.get("/api/orders/{order_id}")
def get_order(order_id: str, authorization: str = Header(None)):
    """
    Возвращает заказ по ID.

    УЯЗВИМОСТЬ (BOLA/IDOR): если order_idor_enabled в профиле,
    владелец заказа не проверяется. Любой авторизованный пользователь
    может получить чужой заказ, зная его ID.
    """
    profile = _profile()

    user_id = _resolve_token(authorization)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        oid = int(order_id)
    except ValueError:
        return {"error": "Invalid ID"}

    order = _ORDERS.get(oid)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # УЯЗВИМОСТЬ: не проверяем, что order["user_id"] == user_id
    if profile.get("order_idor_enabled", True):
        return {"data": order}

    # Правильное поведение
    if order["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"data": order}


# ---------- УЯЗВИМОСТЬ: BFLA в админском эндпоинте ----------
@app.get("/api/admin/users")
def admin_users(authorization: str = Header(None)):
    """
    Список пользователей. Должен быть доступен только админу.

    УЯЗВИМОСТЬ (BFLA): если bfla_enabled в профиле,
    проверка роли не делается, и любой авторизованный (даже обычный user)
    видит список.
    """
    profile = _profile()

    user_id = _resolve_token(authorization)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # УЯЗВИМОСТЬ: нет проверки role == "admin"
    if not profile.get("bfla_enabled", True):
        info = _USERS[user_id]
        if info["role"] != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")

    users = [{"id": uid, "username": info["username"], "role": info["role"]} for uid, info in _USERS.items()]
    return {"data": users}


# ---------- SQLi в /api/users/{user_id} ----------
@app.get("/api/users/{user_id}")
def get_user(user_id: str):
    profile = _profile()

    # УЯЗВИМОСТЬ 1: SQL-инъекция
    if _is_suspicious_input(user_id):
        if not profile.get("sqli_enabled", True):
            return {"data": []}
        if not _maybe(0.9):
            return {"data": []}

    # УЯЗВИМОСТЬ 2: бизнес-логика — отрицательные ID
    # Сервер должен отклонить отрицательный ID, но вместо этого
    # принимает его и возвращает «заглушку» — сканер это ловит.
    stripped = user_id.lstrip("-")
    if stripped.isdigit() and user_id.startswith("-"):
        if not profile.get("business_enabled", True):
            return {"error": "Invalid ID"}
        if not _maybe(0.85):
            return {"error": "Invalid ID"}
        # Возвращаем непустой data — иначе сканер не увидит,
        # что сервер реально принял отрицательный ID.
        return {"data": [{"id": int(user_id), "name": "unknown", "secret": None}]}

    query = f"SELECT name, secret FROM users WHERE id = {user_id}"
    # Свежий курсор на каждый запрос — иначе синхронные роуты FastAPI
    # (они идут в threadpool) могут параллельно дёрнуть один и тот же cursor
    # и получить ProgrammingError: Recursive use of cursors not allowed.
    cur = None
    try:
        cur = conn.cursor()
        cur.execute(query)
        result = cur.fetchall()
        return {"data": result}
    except Exception as e:
        # УЯЗВИМОСТЬ 3: утечка отладочной информации СУБД
        return {"error": str(e)}
    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                pass


# ---------- Утечка чувствительных данных / отсутствие auth ----------
@app.get("/api/system/keys")
def get_keys(authorization: str = Header(None)):
    profile = _profile()

    if not profile.get("idor_enabled", True):
        if not authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")

    if profile.get("sensitive_enabled", True) and _maybe(0.9):
        return {"aws_key": "AKIAIOSFODNN7EXAMPLE", "db_pass": "qwerty"}
    return {"status": "ok"}


# ---------- УЯЗВИМОСТЬ: JWT с alg=none ----------
@app.post("/api/auth/login-jwt")
def login_jwt(body: LoginRequest):
    """
    Логин, возвращающий «JWT».

    УЯЗВИМОСТЬ (Broken Authentication / CVE-2018-0114 style): сервер принимает
    токены с алгоритмом alg=none — атакующий может подделать токен любого
    пользователя, убрав подпись. Если jwt_none_enabled в профиле — проверка
    подписи фактически отсутствует.
    """
    import base64 as _b64
    import json as _json

    for uid, info in _USERS.items():
        if info["username"] == body.username and info["password"] == body.password:
            header = _b64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            payload = (
                _b64.urlsafe_b64encode(_json.dumps({"uid": uid, "role": info["role"]}).encode()).rstrip(b"=").decode()
            )
            sig = _b64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
            return {"token": f"{header}.{payload}.{sig}"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


def _resolve_jwt(authorization: str | None) -> int | None:
    """Разбирает 'JWT'-токен. УЯЗВИМОСТЬ: принимает alg=none без проверки подписи."""
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1]
    seg = token.split(".")
    if len(seg) != 3:
        return None
    try:
        import base64 as _b64
        import json as _json

        pad = lambda s: s + "=" * (-len(s) % 4)
        header = _json.loads(_b64.urlsafe_b64decode(pad(seg[0])))
        if header.get("alg") == "none":
            # УЯЗВИМОСТЬ: подпись не проверяется вовсе
            if not _profile().get("jwt_none_enabled", True):
                return None
            payload = _json.loads(_b64.urlsafe_b64decode(pad(seg[1])))
            return int(payload.get("uid"))
        # «Нормальный» путь: сверка с фиксированным списком токенов
        return _TOKENS.get(token)
    except Exception:
        return None


@app.get("/api/reports/{report_id}")
def get_report(report_id: str, authorization: str = Header(None)):
    """
    Отчёт пользователя. Должен быть доступен только владельцу.

    УЯЗВИМОСТЬ (BOLA через поддельный JWT): если jwt_none_enabled, любой,
    кто собрал токен вида header.payload.(пусто) с alg=none, читает чужие отчёты.
    """
    user_id = _resolve_jwt(authorization)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    owner = ((int(report_id) - 1) % 3) + 1 if report_id.isdigit() else 1
    if _profile().get("jwt_none_enabled", True):
        # УЯЗВИМОСТЬ: владелец отчёта не сверяется с uid из токена
        return {
            "id": report_id,
            "owner_id": owner,
            "finance": {"revenue": 125000, "tax_id": "7712345678"},
        }
    if owner != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"id": report_id, "owner_id": owner}


# ---------- УЯЗВИМОСТЬ: SSRF в загрузке по ссылке ----------
class FetchRequest(BaseModel):
    url: str


@app.post("/api/fetch-url")
def fetch_url(body: FetchRequest):
    """
    «Загрузить содержимое по ссылке» (аватар, превью, вебхук) — сервер сам ходит по URL.

    УЯЗВИМОСТЬ (SSRF): если ssrf_enabled, адрес не проверяется. Можно подсунуть
    внутренний адрес (127.0.0.1 / localhost) или cloud-metadata (169.254.169.254) —
    и сервер вернёт содержимое внутреннего сервиса / метаданные облака.
    """
    url = (body.url or "").strip()
    host = (urlparse(url).hostname or "").lower()
    is_meta = host.startswith("169.254.") or host in ("metadata.google.internal", "fd00:ec2::254")
    is_internal = (
        is_meta or host in ("127.0.0.1", "localhost", "0.0.0.0", "::1") or host.startswith(("10.", "192.168."))
    )

    if not _profile().get("ssrf_enabled", True):
        # Правильное поведение: внутренние адреса и нестандартные схемы запрещены
        if is_internal or urlparse(url).scheme not in ("http", "https"):
            raise HTTPException(status_code=400, detail="URL not allowed")
        return {"source": url, "internal": False, "data": {"title": "Example Domain", "note": "external content"}}

    # УЯЗВИМОСТЬ: без проверки отдаём «внутреннее» содержимое
    if is_meta:
        return {
            "source": url,
            "internal": True,
            "data": {
                "ami-id": "ami-0123456789abcdef0",
                "instance-id": "i-0abcdef1234567890",
                "iam": {
                    "security-credentials": {
                        "scanner-role": {"AccessKeyId": "ASIAEXAMPLE", "SecretAccessKey": "example"}
                    }
                },
            },
        }
    if is_internal:
        return {
            "source": url,
            "internal": True,
            "data": {"service": "internal-admin-panel", "users": ["alice", "bob", "admin"]},
        }
    return {"source": url, "internal": False, "data": {"title": "Example Domain", "note": "external content"}}


# =====================================================================
# Дополнительные учебные уязвимости (симулированные, безопасные).
# Показывают проверки, которые раньше не срабатывали на встроенной цели:
# XSS, Command Injection, GraphQL, SCA, Pagination, Mass Assignment,
# CSRF, Unsafe Methods, Content-Type, Hidden Paths, Open CORS.
# =====================================================================


# ---------- УЯЗВИМОСТЬ: Reflected XSS (HTML-эхо) ----------
@app.get("/api/echo")
def echo(msg: str = ""):
    """Эхо-страница. УЯЗВИМОСТЬ: ввод отражается в HTML без экранирования."""
    return HTMLResponse(f"<html><body><h1>Результат: {msg}</h1></body></html>")


# ---------- УЯЗВИМОСТЬ: OS Command Injection (симуляция, без реального exec) ----------
@app.get("/api/ping")
def ping(host: str = ""):
    """«Пинг» хоста. УЯЗВИМОСТЬ: shell-метасимволы в host «выполняют» команду."""
    if any(c in host for c in ";|&$`"):
        return {"host": host, "output": "uid=0(root) gid=0(root) groups=0(root)"}
    return {"host": host, "output": f"PING {host}: 64 bytes, time=1ms"}


# ---------- УЯЗВИМОСТЬ: GraphQL Introspection ----------
_GRAPHQL_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "kind": "OBJECT"},
                {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "secret"}]},
            ],
        }
    }
}


@app.post("/graphql")
def graphql_post(body: dict):
    """УЯЗВИМОСТЬ: интроспекция схемы доступна без аутентификации."""
    return _GRAPHQL_SCHEMA


@app.get("/graphql")
def graphql_get(query: str = ""):
    return _GRAPHQL_SCHEMA


# ---------- УЯЗВИМОСТЬ: Dependency Manifest Exposed + SCA ----------
@app.get("/requirements.txt", response_class=PlainTextResponse)
def requirements():
    """УЯЗВИМОСТЬ: манифест с устаревшими пиннами доступен извне."""
    return "flask==0.12\nrequests==2.19.1\npyyaml==5.1\n"


# ---------- УЯЗВИМОСТЬ: Missing Pagination ----------
_PRODUCTS = [{"id": i, "name": f"product-{i}", "price": i * 10} for i in range(1, 251)]


@app.get("/api/products")
def products(limit: int = 10000, offset: int = 0):
    """УЯЗВИМОСТЬ: коллекция отдаётся целиком, пагинация не работает."""
    return {"data": _PRODUCTS[offset : offset + limit], "total": len(_PRODUCTS)}


# ---------- УЯЗВИМОСТЬ: Mass Assignment ----------
_PROFILES: dict[int, dict] = {}


@app.post("/api/profile")
async def create_profile(request: Request, authorization: str = Header(None)):
    """УЯЗВИМОСТЬ: сервер принимает и СОХРАНЯЕТ лишние поля (role/is_admin)."""
    uid = _resolve_token(authorization)
    if uid is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        data = await request.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    profile = {"id": uid, "name": data.get("name", "test")}
    if "role" in data:
        profile["role"] = data["role"]
    if "is_admin" in data:
        profile["is_admin"] = data["is_admin"]
    _PROFILES[uid] = profile
    return profile


@app.get("/api/profile")
def get_profile(authorization: str = Header(None)):
    uid = _resolve_token(authorization)
    if uid is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return _PROFILES.get(uid, {"id": uid, "name": "test"})


# ---------- УЯЗВИМОСТЬ: Unsafe HTTP Methods + Content-Type validation ----------
@app.options("/api/legacy")
def legacy_options():
    """УЯЗВИМОСТЬ: разрешены TRACE (XST) и WebDAV-методы."""
    return Response(status_code=200, headers={"Allow": "GET, POST, PUT, DELETE, TRACE, PROPFIND"})


@app.options("/")
def root_options():
    return Response(status_code=200, headers={"Allow": "GET, HEAD, OPTIONS, TRACE"})


@app.post("/api/legacy")
async def legacy_post(request: Request):
    """УЯЗВИМОСТЬ: принимает любой Content-Type (в т.ч. text/plain)."""
    raw = await request.body()
    return {"ok": True, "received": len(raw), "content_type": request.headers.get("content-type", "")}


# ---------- УЯЗВИМОСТЬ: Missing CSRF Protection ----------
@app.post("/api/session/action")
def session_action():
    """State-changing эндпоинт без CSRF-токена (подразумевается cookie-сессия)."""
    return {"ok": True, "action": "performed"}


# ---------- УЯЗВИМОСТЬ: Hidden Paths (не документированы в OpenAPI) ----------
@app.get("/admin", include_in_schema=False)
def hidden_admin():
    return HTMLResponse("<html><body>Admin panel (unlisted)</body></html>")


@app.get("/.env", include_in_schema=False, response_class=PlainTextResponse)
def hidden_env():
    return "DB_PASSWORD=supersecret\nAWS_SECRET_ACCESS_KEY=example\n"


@app.get("/backup", include_in_schema=False)
def hidden_backup():
    return {"backup": "db-2024-01-01.sql", "size": 1048576}


@app.get("/metrics", include_in_schema=False)
def hidden_metrics():
    return PlainTextResponse("requests_total 12345\nerrors_total 3\n")


@app.get("/server-status", include_in_schema=False)
def hidden_status():
    return HTMLResponse("<html><body>Apache server-status</body></html>")


# ---------- УЯЗВИМОСТЬ: Path Traversal / LFI (симуляция чтения файла) ----------
@app.get("/api/file")
def read_file(name: str = ""):
    """УЯЗВИМОСТЬ: имя файла из запроса без проверки — traversal читает /etc/passwd."""
    if ".." in name or "passwd" in name.lower() or "win.ini" in name.lower():
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
    return {"file": name, "content": "sample document"}


# ---------- УЯЗВИМОСТЬ: Open Redirect ----------
@app.get("/api/redirect")
def redirect(next: str = "/"):
    """УЯЗВИМОСТЬ: адрес перехода берётся из параметра next без allowlist."""
    return RedirectResponse(url=next, status_code=302)


# ---------- УЯЗВИМОСТЬ: Insecure Cookie Flags ----------
@app.post("/api/session/login")
def session_login():
    """УЯЗВИМОСТЬ: session-cookie без Secure/HttpOnly/SameSite."""
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session_id", "demo-session", path="/")
    return resp
