"""i18n: RU-only, переключатель удалён."""
import os, re
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = ["index.html", "login.html", "vulns.html"]
def _read(rel): return open(os.path.join(ROOT, rel), encoding="utf-8").read()
def test_i18n_js_exists(): assert os.path.exists(os.path.join(ROOT, "static", "i18n.js"))
def test_screens_have_ru_texts():
    for tpl in TEMPLATES:
        txt = _read(os.path.join("templates", tpl))
        assert "data-i18n" in txt and "/static/i18n.js" in txt and ("СКАНЕР" in txt or "УЯЗВИМОСТЕЙ" in txt)
def test_no_lang_toggle():
    for tpl in TEMPLATES:
        assert 'id="langToggle"' not in _read(os.path.join("templates", tpl))
def test_vulns_ru_invariants_intact():
    txt = _read(os.path.join("templates", "vulns.html"))
    for s in ("СПРАВОЧНИК УЯЗВИМОСТЕЙ", "Все проверки сканера", "Популярные уязвимости"): assert s in txt
