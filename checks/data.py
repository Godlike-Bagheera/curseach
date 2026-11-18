"""Утечка чувствительных данных и манифестов зависимостей."""

import asyncio
import json
import re
from typing import Dict, List, Optional, Tuple

import httpx

from .base import ScanContext, _safe_get, ev
from .descriptions import get_vuln_info


# ================== Sensitive data ==================
async def check_sensitive_data(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    patterns = [
        (r"AKIA[0-9A-Z]{16}",                 "AWS-ключ"),
        (r"BEGIN (RSA|DSA|EC) PRIVATE KEY",   "Приватный ключ"),
        (r"\"password\"\s*:\s*\"[^\"]+\"",    "Пароль в JSON-ответе"),
        (r"\"secret\"\s*:\s*\"[^\"]+\"",      "Секрет в JSON-ответе"),
        (r"\"api[_-]?key\"\s*:\s*\"[^\"]+\"", "API-ключ в JSON-ответе"),
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
        for pattern, desc in patterns:
            if re.search(pattern, body):
                findings.append({
                    "level": "HIGH",
                    "type": "Sensitive Data Exposure",
                    "endpoint": ep,
                    "desc": f"Обнаружены чувствительные данные: {desc}",
                    "details": get_vuln_info("Sensitive Data Exposure"),
                })
                break
    return findings


# ================== SCA ==================
async def check_sca(ctx: ScanContext, endpoints: List[str]) -> List[Dict]:
    findings = []
    for path in ("/package.json", "/requirements.txt", "/pom.xml", "/build.gradle"):
        r = await _safe_get(ctx.client, f"{ctx.target_url}{path}")
        if r is None:
            continue
        if r.status_code == 200:
            findings.append({
                "level": "MEDIUM",
                "type": "Dependency Manifest Exposed",
                "endpoint": path,
                "desc": f"Файл зависимостей {path} доступен извне — раскрывает стек и версии библиотек",
                "details": get_vuln_info("Dependency Manifest Exposed"),
            })
            break
    return findings

# ================== Настоящий SCA через OSV.dev ==================
_OSV_API = "https://api.osv.dev/v1"
_REQ_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)", re.MULTILINE)


def parse_requirements(text: str) -> List[Tuple[str, str]]:
    """Пиннутые зависимости из requirements.txt (name==version)."""
    return [(m.group(1), m.group(2)) for m in _REQ_PIN_RE.finditer(text or "")]


def parse_package_json(text: str) -> List[Tuple[str, str]]:
    """Точные версии из package.json (dependencies + devDependencies)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: List[Tuple[str, str]] = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if not isinstance(ver, str):
                continue
            v = ver.lstrip("^~>=<v ").strip()
            if not v or not v[0].isdigit() or any(c in v for c in " *|") or "git" in v or "http" in v:
                continue
            out.append((name, v))
    return out


def _osv_severity(doc: dict) -> Tuple[str, str]:
    """Уровень находки по данным OSV (GHSA severity / CVSS)."""
    db_sev = str((doc.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
               "MEDIUM": "MEDIUM", "LOW": "LOW"}
    if db_sev in mapping:
        return mapping[db_sev], db_sev
    for s in doc.get("severity") or []:
        score = str(s.get("score", ""))
        try:
            val = float(score)
            if val >= 9.0:
                return "CRITICAL", score
            if val >= 7.0:
                return "HIGH", score
            if val >= 4.0:
                return "MEDIUM", score
            return "LOW", score
        except ValueError:
            continue
    # Уязвимость подтверждена базой OSV, но severity не указан — консервативно HIGH.
    return "HIGH", ""


def _fixed_versions(doc: dict, name: str, ecosystem: str) -> List[str]:
    fixed: List[str] = []
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for ev_ in rng.get("events") or []:
                if "fixed" in ev_:
                    fixed.append(ev_["fixed"])
    return sorted(set(fixed))


async def _osv_lookup(deps: List[Tuple[str, str, str]], client=None) -> List[Tuple[Tuple[str, str, str], dict]]:
    """deps: (name, version, ecosystem). Возвращает пары (dep, vuln_doc)."""
    if not deps:
        return []
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=10.0)
    try:
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v}
                   for n, v, eco in deps[:100]]
        r = await client.post(f"{_OSV_API}/querybatch", json={"queries": queries})
        if r.status_code != 200:
            return []
        results = r.json().get("results") or []
        wanted: List[Tuple[Tuple[str, str, str], str]] = []
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
                try:
                    rr = await client.get(f"{_OSV_API}/vulns/{vid}")
                    if rr.status_code == 200:
                        return rr.json()
                except (httpx.HTTPError, ValueError):
                    pass
                return None

        docs = await asyncio.gather(*(get_doc(vid) for _, vid in wanted[:25]))
        return [(dep, doc) for (dep, _), doc in zip(wanted[:25], docs) if doc]
    except (httpx.HTTPError, ValueError):
        return []
    finally:
        if own:
            await client.aclose()


async def check_osv_sca(ctx: ScanContext, endpoints: List[str], osv_client=None) -> List[Dict]:
    """
    Настоящий SCA: парсит пиннутые версии из доступных манифестов и
    сверяет их с базой OSV.dev (CVE/GHSA). Сетевые ошибки OSV не роняют скан.
    """
    deps: List[Tuple[str, str, str]] = []
    manifest_of: Dict[Tuple[str, str], str] = {}
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

    pairs = await _osv_lookup(deps, client=osv_client)
    findings: List[Dict] = []
    for (n, v, eco), doc in pairs:
        level, score = _osv_severity(doc)
        vid = doc.get("id", "")
        aliases = doc.get("aliases") or []
        cves = [a for a in aliases if a.startswith("CVE-")]
        summary = (doc.get("summary") or doc.get("details") or "")[:140]
        fixed = _fixed_versions(doc, n, eco)
        findings.append({
            "level": level,
            "type": "Vulnerable Dependency (OSV)",
            "endpoint": manifest_of.get((n, v), "/requirements.txt"),
            "desc": f"{n}=={v}: {vid} ({', '.join(cves) if cves else vid}) — {summary}",
            "details": get_vuln_info("Vulnerable Dependency (OSV)"),
            "confidence": "high",
            "evidence": {
                "osv_id": vid, "aliases": aliases, "package": n,
                "version": v, "ecosystem": eco, "fixed": fixed,
                "severity_score": score,
            },
        })
    return findings
