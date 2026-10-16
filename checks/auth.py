"""
Проверки, связанные с аутентификацией и разграничением прав:
- check_cross_user_idor: user1 читает данные user2 (BOLA / IDOR)
- check_bfla: обычный user получает доступ к админскому эндпоинту
"""

from typing import Dict, List

import httpx

from .base import (
    ScanContext,
    _safe_get,
    _content_hash,
)
from .descriptions import get_vuln_info


# ---------- Вспомогательное ----------
_ID_RANGE = list(range(1, 11))


async def _collect_200(
    client, target_url: str, ep: str, param_name: str
) -> Dict[int, httpx.Response]:
    """Ходит к /endpoint/{id} для id из _ID_RANGE, возвращает только те, что дали 200."""
    out: Dict[int, httpx.Response] = {}
    for i in _ID_RANGE:
        path = ep.replace(f"{{{param_name}}}", str(i))
        r = await _safe_get(client, f"{target_url}{path}")
        if r is not None and r.status_code == 200:
            out[i] = r
    return out


def _extract_ids_from_payload(payload) -> set:
    """
    Рекурсивно достаёт все целочисленные значения ключей 'id' / 'order_id' / '_id'.
    Работает и для dict, и для списка, и для вложенных структур.
    """
    ids = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ("id", "order_id", "_id") and isinstance(v, int):
                    ids.add(v)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return ids


# ================== Cross-user IDOR (BOLA) ==================
async def check_cross_user_idor(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    """
    Проверка на cross-user IDOR (Broken Object Level Authorization).

    Требует ДВА разных токена (user1 и user2). Логика:

    1. Ищем «me»-эндпоинты (в пути есть /me, /my, /profile, /orders, /account),
       которые возвращают список своих объектов.
    2. Ходим туда user1 → получаем S1 (набор своих ID).
    3. Ходим туда user2 → получаем S2 (набор своих ID).
    4. Если S1 и S2 непустые и не пересекаются — картина чёткая.
    5. Ищем param-эндпоинты (/api/orders/{order_id} и т. п.).
    6. Для каждого ID из S2 пробуем user1: если 200 → чужой ресурс доступен → CRITICAL.

    Fallback (если «me»-эндпоинтов нет): сравниваем, что user1 и user2
    видят на одних и тех же ID. Если оба получают 200 с одинаковым телом
    на ≥2 объектах — эвристически помечаем MEDIUM.
    """
    if not ctx.has_auth or not ctx.has_auth_secondary or ctx.secondary_client is None:
        return []

    findings: List[Dict] = []

    # ---- 1. Ищем «me»-эндпоинты со списками ----
    list_endpoints = [
        e for e in endpoints
        if "{" not in e and "}" not in e
        and any(k in e.lower() for k in ("/me", "/my", "/profile", "/account"))
    ]

    user1_ids: set = set()
    user2_ids: set = set()

    for ep in list_endpoints:
        r1 = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        if r1 is not None and r1.status_code == 200:
            try:
                user1_ids |= _extract_ids_from_payload(r1.json())
            except ValueError:
                pass

        r2 = await _safe_get(ctx.secondary_client, f"{ctx.target_url}{ep}")
        if r2 is not None and r2.status_code == 200:
            try:
                user2_ids |= _extract_ids_from_payload(r2.json())
            except ValueError:
                pass

    # ---- 2. Основной сценарий: есть чёткие списки «своих» ----
    if user1_ids and user2_ids and not (user1_ids & user2_ids):
        param_endpoints = [p for p in endpoints if "{" in p and "}" in p]

        for ep in param_endpoints:
            # Пропускаем /api/users/{...} — там SQLi, отдельная проверка
            if "/api/users/" in ep:
                continue

            param_name = ep[ep.find("{") + 1:ep.find("}")]
            foreign_ids = sorted(user2_ids)[:5]
            leaked = []

            for oid in foreign_ids:
                path = ep.replace(f"{{{param_name}}}", str(oid))
                r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
                if r is not None and r.status_code == 200:
                    leaked.append(oid)

            if leaked:
                findings.append({
                    "level": "CRITICAL",
                    "type": "Broken Access Control",
                    "endpoint": ep,
                    "desc": (
                        f"Cross-user IDOR (BOLA): user1 получает доступ к "
                        f"чужим объектам через {param_name} "
                        f"(ID: {', '.join(map(str, leaked))})"
                    ),
                    "details": get_vuln_info("Broken Access Control"),
                })

        return findings

    # ---- 3. Fallback: нет чётких списков, но есть два токена ----
    param_endpoints = [p for p in endpoints if "{" in p and "}" in p]

    for ep in param_endpoints:
        if "/api/users/" in ep:
            continue

        param_name = ep[ep.find("{") + 1:ep.find("}")]

        user1_ok = await _collect_200(ctx.client, ctx.target_url, ep, param_name)
        if not user1_ok:
            continue

        user2_ok = await _collect_200(ctx.secondary_client, ctx.target_url, ep, param_name)
        if not user2_ok:
            continue

        shared_ids = set(user1_ok.keys()) & set(user2_ok.keys())
        if len(shared_ids) < 2:
            continue

        same_content = sum(
            1 for oid in shared_ids
            if _content_hash(user1_ok[oid]) == _content_hash(user2_ok[oid])
        )

        if same_content == len(shared_ids):
            findings.append({
                "level": "MEDIUM",
                "type": "Broken Access Control",
                "endpoint": ep,
                "desc": (
                    f"Эвристика: user1 и user2 получают одинаковый контент "
                    f"на {same_content} объектах через {param_name} — "
                    f"возможно, нет разделения по пользователям"
                ),
                "details": get_vuln_info("Broken Access Control"),
            })

    return findings


# ================== BFLA (Broken Function Level Authorization) ==================
async def check_bfla(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    """
    Проверка на BFLA: обычный пользователь получает доступ к эндпоинту,
    который должен быть только для админа.

    Эвристика:
    - ищем эндпоинты, в пути которых есть admin/manage/internal/superuser/settings;
    - user1 (обычный) должен получать НЕ 200 (403/401);
    - если user1 получает 200 — и аноним тоже нет, значит, авторизация
      работает, но проверки роли нет → BFLA.
    """
    if not ctx.has_auth:
        return []

    admin_keywords = ("admin", "manage", "internal", "superuser", "settings", "config")
    candidates = [
        e for e in endpoints
        if "{" not in e and "}" not in e
        and any(k in e.lower() for k in admin_keywords)
    ]

    findings: List[Dict] = []

    for ep in candidates:
        # 1. user1 → должен получить 403/401 (если разделение ролей корректное)
        r1 = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        if r1 is None or r1.status_code != 200:
            continue

        # 2. Аноним → если тоже 200, это уже не BFLA, а открытый эндпоинт (другая проверка)
        r_anon = await _safe_get(ctx.anon_client, f"{ctx.target_url}{ep}")
        if r_anon is not None and r_anon.status_code == 200:
            continue

        # 3. Если есть user2 — сравним, что оба видят одно и то же.
        #    Если user2 тоже получил 200 с тем же телом — это чистый BFLA.
        #    Если user2 упал (r2 is None или не 200) — падаем в эвристику ниже.
        secondary_confirmed = False
        if ctx.has_auth_secondary and ctx.secondary_client is not None:
            r2 = await _safe_get(ctx.secondary_client, f"{ctx.target_url}{ep}")
            if r2 is not None and r2.status_code == 200:
                if _content_hash(r1) == _content_hash(r2):
                    findings.append({
                        "level": "CRITICAL",
                        "type": "Broken Access Control",
                        "endpoint": ep,
                        "desc": (
                            f"BFLA: обычные пользователи (user1 и user2) получают "
                            f"доступ к административному эндпоинту {ep}"
                        ),
                        "details": get_vuln_info("Broken Access Control"),
                    })
                    continue
                # user2 отдал 200, но контент разный — не наш случай, идём в эвристику
                secondary_confirmed = True

        # 4. Эвристика по содержимому ответа.
        #    Срабатывает и когда второго токена нет, и когда он упал,
        #    и когда он дал 200 с другим телом.
        if not secondary_confirmed:
            body = r1.text.lower()
            if any(k in body for k in ("users", "config", "settings",
                                       "internal", "password", "secret", "role")):
                findings.append({
                    "level": "HIGH",
                    "type": "Broken Access Control",
                    "endpoint": ep,
                    "desc": (
                        f"BFLA (эвристика): эндпоинт {ep} выглядит административным, "
                        f"но доступен обычному токену"
                    ),
                    "details": get_vuln_info("Broken Access Control"),
                })

    return findings