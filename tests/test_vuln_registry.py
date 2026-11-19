"""Реестр /vulns синхронизирован с CHECK_METADATA и descriptions."""
from checks import CHECK_METADATA
from scanner.vuln_guide import build_guide, build_registry, slugify


def test_registry_covers_all_checks():
    reg = build_registry()
    assert {r["id"] for r in reg} == set(CHECK_METADATA)
    assert len(reg) == len(CHECK_METADATA)


def test_registry_entries_have_meaning_and_tags():
    for r in build_registry():
        assert r["meaning"], r["id"]
        assert r["recommendation"], r["id"]
        assert r["level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert r["search"]


def test_guide_slugs_and_search():
    guide = build_guide()
    assert len(guide) == 15
    for g in guide:
        assert g["slug"] == slugify(g["en"])
        assert g["en"].lower() in g["search"]
        assert g["ru"].lower() in g["search"]
    sqli = next(g for g in guide if g["en"] == "SQL Injection")
    assert "cwe-89" in sqli["search"]
    assert "check_sqli" in sqli["search"]


def test_registry_links_to_guide():
    reg = {r["id"]: r for r in build_registry()}
    assert reg["check_sqli"]["guide_slug"] == "sql-injection"
    assert reg["check_cors"]["guide_slug"] is None
    assert reg["check_cors"]["vuln_type"] == "Open CORS"
