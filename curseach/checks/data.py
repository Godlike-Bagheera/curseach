"""Утечка чувствительных данных и SCA (уязвимые зависимости)."""

import re
from typing import Dict, List

from .base import ScanContext, _safe_get
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
                "level": "CRITICAL",
                "type": "Vulnerable Dependencies (SCA)",
                "endpoint": path,
                "desc": f"Обнаружен файл зависимостей {path}",
                "details": get_vuln_info("Vulnerable Dependencies (SCA)"),
            })
            break
    return findings