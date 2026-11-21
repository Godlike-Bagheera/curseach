"""Утечка чувствительных данных и манифестов зависимостей."""

import asyncio
import json
import math
import re

import httpx

from .base import ScanCancelled, ScanContext, _safe_get
from .descriptions import get_vuln_info

# ================== Sensitive data ==================
_SECRET_PLACEHOLDERS = {
    "string",
    "password",
    "secret",
    "changeme",
    "change_me",
    "example",
    "test",
    "your_password",
    "your_secret",
    "your_api_key",
    "null",
    "none",
    "undefined",
    "placeholder",
    "redacted",
    "hidden",
    "masked",
    "dummy",
    "sample",
    "default",
}


def _is_real_secret(value: str) -> bool:
    """Placeholder/маска/пустышка — не утечка секрета (Swagger-example «string», «********», «<hidden>»)."""
    v = (value or "").strip()
    if len(v) < 6:
        return False
    low = v.lower()
    if low in _SECRET_PLACEHOLDERS:
        return False
    if re.fullmatch(r"[*•·x#.\-]+", low):
        return False
    if re.fullmatch(r"<[^>]*>|\[[^\]]*\]", low):
        return False
    if any(w in low for w in ("your_", "example", "changeme", "placeholder")):
        return False
    return True


async def check_sensitive_data(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    strong_patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS-ключ"),
        (r"BEGIN (RSA|DSA|EC) PRIVATE KEY", "Приватный ключ"),
    ]
    value_patterns = [
        (r"\"password\"\s*:\s*\"([^\"]+)\"", "Пароль в JSON-ответе"),
        (r"\"secret\"\s*:\s*\"([^\"]+)\"", "Секрет в JSON-ответе"),
        (r"\"api[_-]?key\"\s*:\s*\"([^\"]+)\"", "API-ключ в JSON-ответе"),
    ]
    for ep in endpoints:
        if "{" in ep or "}" in ep:
            continue
        r = await _safe_get(ctx.client, f"{ctx.target_url}{ep}")
        if r is None or r.status_code != 200:
            continue
        try:
            body = r.text
        except (UnicodeDecodeError, LookupError):
            continue
        hit = None
        for pattern, desc in strong_patterns:
            if re.search(pattern, body):
                hit = desc
                break
        if hit is None:
            for pattern, desc in value_patterns:
                m = re.search(pattern, body)
                if m and _is_real_secret(m.group(1)):
                    hit = desc
                    break
        if hit:
            findings.append(
                {
                    "level": "HIGH",
                    "type": "Sensitive Data Exposure",
                    "endpoint": ep,
                    "desc": f"Обнаружены чувствительные данные: {hit}",
                    "details": get_vuln_info("Sensitive Data Exposure"),
                }
            )
    return findings


# ================== SCA ==================
def _looks_like_manifest(path: str, text: str) -> bool:
    """Голый HTTP 200 не доказывает манифест: SPA/catch-all вернёт index.html.
    Валидируем содержимое, чтобы не было ложных срабатываний."""
    t = (text or "").strip()
    if not t:
        return False
    low = t[:300].lower()
    if "<html" in low or "<!doctype html" in low:
        return False
    if path.endswith(".json"):
        try:
            data = json.loads(t)
        except ValueError:
            return False
        return isinstance(data, dict) and any(
            k in data for k in ("dependencies", "devDependencies", "name", "packages")
        )
    if path.endswith("requirements.txt"):
        return bool(_REQ_PIN_RE.search(t)) or bool(re.search(r"^\s*[A-Za-z0-9_.\-]+\s*[><=~!]", t, re.MULTILINE))
    if path.endswith(".xml"):
        return "<project" in low or "<packages" in low or "<?xml" in low
    if path.endswith(".gradle"):
        return any(k in low for k in ("dependencies", "implementation", "compile"))
    return False


async def check_sca(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    findings: list = []
    for path in ("/package.json", "/requirements.txt", "/pom.xml", "/build.gradle"):
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None:
            continue
        try:
            text = r.text
        except (UnicodeDecodeError, LookupError):
            continue
        if r.status_code == 200 and _looks_like_manifest(path, text):
            findings.append(
                {
                    "level": "MEDIUM",
                    "type": "Dependency Manifest Exposed",
                    "endpoint": path,
                    "desc": f"Файл зависимостей {path} доступен извне — раскрывает стек и версии библиотек",
                    "details": get_vuln_info("Dependency Manifest Exposed"),
                }
            )
            break
    return findings


# ================== Настоящий SCA через OSV.dev ==================
_OSV_API = "https://api.osv.dev/v1"
_REQ_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)", re.MULTILINE)


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Пиннутые зависимости из requirements.txt (name==version)."""
    return [(m.group(1), m.group(2)) for m in _REQ_PIN_RE.finditer(text or "")]


def parse_package_json(text: str) -> list[tuple[str, str]]:
    """Точные версии из package.json (dependencies + devDependencies)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if not isinstance(ver, str):
                continue
            v = ver.strip()
            # Только ТОЧНЫЕ пины (x.y.z). Диапазоны (^4.17.4, >=1.2.3, *)
            # не являются установленной версией — OSV по ним даёт FP/FN.
            if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?", v):
                continue
            out.append((name, v.lstrip("v")))
    return out


def _cvss_v3_score(vector: str) -> float | None:
    """Базовый балл CVSS v3.x из вектора (CVSS:3.1/AV:N/…). Без внешних зависимостей."""
    parts = {}
    for chunk in (vector or "").split("/"):
        if ":" in chunk:
            k, _, val = chunk.partition(":")
            parts[k.upper()] = val.upper()
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(parts.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", ""))
    scope = parts.get("S", "")
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    c, i, a = (cia.get(parts.get(k, "")) for k in ("C", "I", "A"))
    pr_map = {"N": 0.85, "L": 0.68 if scope == "C" else 0.62, "H": 0.50 if scope == "C" else 0.27}
    pr = pr_map.get(parts.get("PR", ""))
    if None in (av, ac, ui, pr, c, i, a) or scope not in ("U", "C"):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min(impact + exploit, 10) if scope == "U" else min(1.08 * (impact + exploit), 10)
    return math.ceil(round(raw, 6) * 10) / 10.0


def _osv_severity(doc: dict) -> tuple[str, str]:
    """Уровень находки по данным OSV (GHSA severity / CVSS)."""
    db_sev = str((doc.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    if db_sev in mapping:
        return mapping[db_sev], db_sev
    for s in doc.get("severity") or []:
        score = str(s.get("score", ""))
        val = None
        try:
            val = float(score)
        except ValueError:
            # OSV часто отдаёт CVSS-ВЕКТОР, а не число: раньше float() падал
            # и всё сваливалось в консервативный HIGH.
            if score.upper().startswith("CVSS:3"):
                val = _cvss_v3_score(score)
        if val is None:
            continue
        if val >= 9.0:
            return "CRITICAL", score
        if val >= 7.0:
            return "HIGH", score
        if val >= 4.0:
            return "MEDIUM", score
        return "LOW", score
    # Уязвимость подтверждена базой OSV, но severity не указан — консервативно HIGH.
    return "HIGH", ""


def _fixed_versions(doc: dict, name: str, ecosystem: str) -> list[str]:
    fixed: list[str] = []
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for ev_ in rng.get("events") or []:
                if "fixed" in ev_:
                    fixed.append(ev_["fixed"])
    return sorted(set(fixed))


async def _osv_lookup(
    deps: list[tuple[str, str, str]], client=None, cancel_event=None
) -> list[tuple[tuple[str, str, str], dict]]:
    """deps: (name, version, ecosystem). Возвращает пары (dep, vuln_doc).

    Запросы идут во внешний API OSV (не к цели), поэтому в бюджет цели не
    засчитываются; но отмена скана должна прерывать и их (cancel_event).
    """
    if not deps:
        return []
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled()
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=10.0)
    try:
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v, eco in deps[:100]]
        r = await client.post(f"{_OSV_API}/querybatch", json={"queries": queries})
        if r.status_code != 200:
            return []
        results = r.json().get("results") or []
        wanted: list[tuple[tuple[str, str, str], str]] = []
        seen_ids = set()
        for i, res in enumerate(results):
            if i >= len(deps):
                break
            for v in (res or {}).get("vulns") or []:
                vid = v.get("id")
                if vid and (vid, i) not in seen_ids:
                    seen_ids.add((vid, i))
                    wanted.append((deps[i], vid))
        sem = asyncio.Semaphore(5)

        async def get_doc(vid: str):
            async with sem:
                if cancel_event is not None and cancel_event.is_set():
                    raise ScanCancelled()
                try:
                    rr = await client.get(f"{_OSV_API}/vulns/{vid}")
                    if rr.status_code == 200:
                        return rr.json()
                except (httpx.HTTPError, ValueError):
                    pass
                return None

        docs = await asyncio.gather(*(get_doc(vid) for _, vid in wanted[:25]))
        return [(dep, doc) for (dep, _), doc in zip(wanted[:25], docs, strict=True) if doc]
    except (httpx.HTTPError, ValueError):
        return []
    finally:
        if own:
            await client.aclose()


async def check_osv_sca(ctx: ScanContext, endpoints: list[str], osv_client=None) -> list[dict]:
    """
    Настоящий SCA: парсит пиннутые версии из доступных манифестов и
    сверяет их с базой OSV.dev (CVE/GHSA). Сетевые ошибки OSV не роняют скан.
    """
    deps: list[tuple[str, str, str]] = []
    manifest_of: dict[tuple[str, str], str] = {}
    for path, eco, parser in (
        ("/requirements.txt", "PyPI", parse_requirements),
        ("/package.json", "npm", parse_package_json),
    ):
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None or r.status_code != 200:
            continue
        try:
            text = r.text
        except (UnicodeDecodeError, LookupError):
            continue
        for n, v in parser(text)[:50]:
            deps.append((n, v, eco))
            manifest_of[(n, v)] = path
    if not deps:
        return []

    pairs = await _osv_lookup(deps, client=osv_client, cancel_event=ctx.cancel_event)
    findings: list[dict] = []
    for (n, v, eco), doc in pairs:
        level, score = _osv_severity(doc)
        vid = doc.get("id", "")
        aliases = doc.get("aliases") or []
        cves = [a for a in aliases if a.startswith("CVE-")]
        summary = (doc.get("summary") or doc.get("details") or "")[:140]
        fixed = _fixed_versions(doc, n, eco)
        findings.append(
            {
                "level": level,
                "type": "Vulnerable Dependency (OSV)",
                "endpoint": manifest_of.get((n, v), "/requirements.txt"),
                "desc": f"{n}=={v}: {vid} ({', '.join(cves) if cves else vid}) — {summary}",
                "details": get_vuln_info("Vulnerable Dependency (OSV)"),
                "confidence": "high",
                "evidence": {
                    "osv_id": vid,
                    "aliases": aliases,
                    "package": n,
                    "version": v,
                    "ecosystem": eco,
                    "fixed": fixed,
                    "severity_score": score,
                },
            }
        )
    return findings
