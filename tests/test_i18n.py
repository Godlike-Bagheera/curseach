"""i18n-каркас: словарь EN покрывает data-i18n ключи главного экрана (ROADMAP 8)."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_i18n_js_exists():
    assert os.path.exists(os.path.join(ROOT, "static", "i18n.js"))


def test_index_has_i18n_hooks():
    txt = open(os.path.join(ROOT, "templates", "index.html"), encoding="utf-8").read()
    assert "data-i18n" in txt
    assert 'id="langToggle"' in txt
    assert "/static/i18n.js" in txt


def test_i18n_keys_covered():
    idx = open(os.path.join(ROOT, "templates", "index.html"), encoding="utf-8").read()
    js = open(os.path.join(ROOT, "static", "i18n.js"), encoding="utf-8").read()
    keys = set(re.findall(r'data-i18n="([^"]+)"', idx))
    assert keys
    for k in keys:
        assert f"'{k}'" in js, f"нет EN-перевода для {k}"
