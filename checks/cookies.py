"""Флаги безопасности cookie (Secure / HttpOnly / SameSite)."""

from .base import ScanContext, _safe_get, _safe_post, ev
from .descriptions import get_vuln_info


async def check_cookie_flags(ctx: ScanContext, endpoints: list[str]) -> list[dict]:
    """Собираем Set-Cookie с корня, статических эндпоинтов и login/session-точек."""
    findings: list[dict] = []
    static = [e for e in (endpoints or []) if "{" not in e and "}" not in e]
    probes: list[tuple[str, str]] = [("/", "GET")] + [(e, "GET") for e in static[:4]]
    probes += [(e, "POST") for e in (endpoints or []) if "login" in e.lower() or "session" in e.lower()][:3]
    seen: set = set()
    for path, method in probes:
        url = f"{ctx.target_url}{path}"
        r = await (_safe_get(ctx.client, url) if method == "GET" else _safe_post(ctx.client, url, json={}))
        if r is None:
            continue
        for sc in r.headers.get_list("set-cookie"):
            name = sc.split("=", 1)[0].strip()
            low = sc.lower()
            issues = []
            if "secure" not in low:
                issues.append("нет Secure")
            if "httponly" not in low:
                issues.append("нет HttpOnly")
            if "samesite" not in low:
                issues.append("нет SameSite")
            if issues and name not in seen:
                seen.add(name)
                findings.append(
                    {
                        "level": "MEDIUM",
                        "type": "Insecure Cookie Flags",
                        "endpoint": path,
                        "method": method,
                        "desc": f"Cookie «{name}»: {', '.join(issues)}",
                        "confidence": "high",
                        "details": get_vuln_info("Insecure Cookie Flags"),
                        "evidence": ev(r),
                    }
                )
    return findings
