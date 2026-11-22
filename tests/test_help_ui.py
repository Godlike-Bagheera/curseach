"""«?»-подсказки на главной: покрытие всех проверок + подключение help.js."""

import os

from checks import CHECK_METADATA

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(p):
    return open(os.path.join(ROOT, p), encoding="utf-8").read()


def test_help_covers_all_checks():
    js = _read("static/help.js")
    for cid in CHECK_METADATA:
        assert cid + ":" in js, cid


def test_help_ru_only():
    js = _read("static/help.js")
    assert "ru:" in js
    assert ", en:" not in js


def test_index_loads_help_js():
    assert "/static/help.js" in _read("templates/index.html")


def test_renderchecks_adds_help_button():
    js = _read("static/script.js")
    assert "help-q" in js and "'check:' + c.id" in js


def test_help_css_present():
    css = _read("static/style.css")
    assert ".help-q" in css and ".help-tip" in css
