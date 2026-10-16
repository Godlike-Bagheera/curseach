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
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Damn Vulnerable API", version="1.0")

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
    2: {"username": "bob",   "password": "bob123",   "role": "user"},
    3: {"username": "admin", "password": "admin123", "role": "admin"},
}

# Простая схема: токен = фиксированная строка, привязанная к user_id.
# В реальной жизни был бы JWT/HMAC; здесь — для учебной цели.
_TOKENS = {
    "token_alice_aaa111": 1,
    "token_bob_bbb222":   2,
    "token_admin_ccc333": 3,
}

# Заказы: id -> {user_id, item, price}
_ORDERS = {
    1: {"id": 1, "user_id": 1, "item": "laptop",   "price": 1200},
    2: {"id": 2, "user_id": 1, "item": "mouse",    "price": 25},
    3: {"id": 3, "user_id": 2, "item": "keyboard", "price": 80},
    4: {"id": 4, "user_id": 2, "item": "monitor",  "price": 350},
    5: {"id": 5, "user_id": 3, "item": "server",   "price": 5000},
}


def _resolve_token(authorization: Optional[str]) -> Optional[int]:
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


def _new_scan():
    """Генерирует новый профиль уязвимостей для одного скана."""
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
        "idor_enabled": rng.random() < 0.90,           # /api/system/keys без auth
        "order_idor_enabled": rng.random() < 0.80,     # /api/orders/{id}: без проверки владельца
        "bfla_enabled": rng.random() < 0.80,           # /api/admin/users: без проверки роли
        "sensitive_enabled": rng.random() < 0.75,
        "business_enabled": rng.random() < 0.75,
        "global_bias": rng.uniform(0.7, 1.3),
    }


_new_scan()  # инициализация при старте сервера


def _profile() -> dict:
    return _state["profile"]


def _maybe(prob: float) -> bool:
    """Бросок кубика с учётом глобального bias-а текущего скана."""
    rng = _state["rng"]
    bias = _state["profile"].get("global_bias", 1.0)
    adjusted = min(1.0, max(0.0, prob * bias))
    return rng.random() < adjusted


def _is_suspicious_input(value: str) -> bool:
    """Эвристика: содержит ли ввод SQL-подобные маркеры."""
    markers = ("'", '"', "--", ";", "UNION", "SELECT", "SLEEP",
               "WAITFOR", "PG_SLEEP", " OR ", " AND ")
    upper = value.upper()
    return any(m in upper for m in markers)


# ---------- Middleware ----------
@app.middleware("http")
async def randomized_middleware(request, call_next):
    # Новый скан стартует только по явному заголовку X-Scan-Start: 1.
    if request.url.path == "/openapi.json" and request.headers.get("x-scan-start") == "1":
        _new_scan()

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

    users = [
        {"id": uid, "username": info["username"], "role": info["role"]}
        for uid, info in _USERS.items()
    ]
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
        return {
            "data": [
                {"id": int(user_id), "name": "unknown", "secret": None}
            ]
        }

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