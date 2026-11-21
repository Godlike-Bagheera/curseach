"""i18n: словарь EN покрывает data-i18n ключи index/login/vulns (ROADMAP 8)."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = ["index.html", "login.html", "vulns.html"]


def _read(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


def test_i18n_js_exists():
    assert os.path.exists(os.path.join(ROOT, "static", "i18n.js"))


def test_screens_have_i18n_hooks():
    for tpl in TEMPLATES:
        txt = _read(os.path.join("templates", tpl))
        assert "data-i18n" in txt, tpl
        assert 'id="langToggle"' in txt, tpl
        assert "/static/i18n.js" in txt, tpl


def test_i18n_keys_covered():
    js = _read(os.path.join("static", "i18n.js"))
    keys = set()
    for tpl in TEMPLATES:
        txt = _read(os.path.join("templates", tpl))
        keys |= set(re.findall(r'data-i18n="([^"]+)"', txt))
        keys |= set(re.findall(r'data-i18n-placeholder="([^"]+)"', txt))
    assert keys
    for k in keys:
        assert f"'{k}'" in js, f"нет EN-перевода для {k}"


def test_vulns_ru_invariants_intact():
    txt = _read(os.path.join("templates", "vulns.html"))
    for s in ("СПРАВОЧНИК УЯЗВИМОСТЕЙ", "Все проверки сканера", "Популярные уязвимости", "Как читать справочник"):
        assert s in txt
