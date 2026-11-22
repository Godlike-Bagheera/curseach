"""i18n: интерфейс только на русском — переключатель удалён, RU-тексты зашиты в шаблоны."""

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
        assert "/static/i18n.js" in txt, tpl


def test_no_lang_toggle_anywhere():
    for tpl in TEMPLATES:
        assert 'id="langToggle"' not in _read(os.path.join("templates", tpl)), tpl
    js = _read(os.path.join("static", "i18n.js"))
    assert "langToggle" not in js
    assert "curseach.lang" not in js


def test_i18n_ru_only():
    js = _read(os.path.join("static", "i18n.js"))
    assert "getLang" in js and "'ru'" in js
    assert "SCANNER" not in js  # EN-словарь удалён
    for tpl in TEMPLATES:
        assert 'lang="ru"' in _read(os.path.join("templates", tpl)), tpl


def test_data_i18n_nodes_contain_ru_text():
    txt = _read(os.path.join("templates", "index.html"))
    nodes = re.findall(r'data-i18n="[^"]+"[^>]*>([^<]+)<', txt)
    assert nodes
    assert any(re.search(r"[А-Яа-яЁё]", n) for n in nodes)


def test_vulns_ru_invariants_intact():
    txt = _read(os.path.join("templates", "vulns.html"))
    for s in ("СПРАВОЧНИК УЯЗВИМОСТЕЙ", "Все проверки сканера", "Популярные уязвимости", "Как читать справочник"):
        assert s in txt
