"""Валидность SARIF для GitHub Code Scanning (регрессия columnKind)."""

from scanner.reporting import results_to_sarif


def test_sarif_column_kind_and_enrichment():
    sarif = results_to_sarif(
        "http://t",
        "2026-01-01",
        [
            {
                "level": "CRITICAL",
                "type": "SQL Injection",
                "desc": "d",
                "endpoint": "/api/users/{user_id}",
                "details": {"cwe": ["CWE-89"], "owasp_api": ["API8:2023"], "plain": "p"},
                "confidence": "high",
                "evidence": {"method": "GET", "url": "http://t/x", "status": 200, "response_body": "sqlite error"},
            }
        ],
    )
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    # GitHub отклоняет SARIF с columnKind != utf16CodeUnits/unicodeCodePoints
    assert run["columnKind"] == "utf16CodeUnits"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"
    assert "CWE-89" in rule["properties"]["tags"]
    res = run["results"][0]
    assert res["level"] == "error"
    assert "CWE-89" in res["properties"]["tags"]
    assert "Evidence" in res["message"]["text"]
    assert res["properties"]["confidence"] == "high"
    # GitHub требует относительный uri (без http-схемы)
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "api/users/user_id" and "://" not in uri
    assert res["properties"]["targetUrl"] == "http://t"
    # automationDetails.id — стабильная категория по цели, БЕЗ времени прогона:
    # иначе каждый аплоад создаёт новую категорию и GitHub не дедуплицирует алерты.
    assert run["automationDetails"]["id"] == "devsecops/t"
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is True
    # endTimeUtc — UTC по спеке SARIF (суффикс Z), МСК — отдельным полем.
    assert inv["endTimeUtc"] == "2026-01-01T00:00:00Z"
    assert inv["properties"]["scanDateMsk"] == "2026-01-01 03:00:00"
