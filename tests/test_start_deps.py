"""Юнит-тесты requirements-driven бутстрапа start.py."""

import start


def test_parse_pins():
    txt = (
        "# comment\n-r other.txt\nfastapi==0.163.1\nuvicorn[standard]==0.54.0\n"
        "httpx==0.28.1 ; python_version>='3.9'\n\nnoversion\n"
    )
    assert start._parse_pins(txt) == [("fastapi", "0.163.1"), ("uvicorn", "0.54.0"), ("httpx", "0.28.1")]


def test_missing_logic(monkeypatch):
    installed = {"fastapi": "0.163.1", "httpx": "0.27.0"}
    monkeypatch.setattr(start, "_installed_version", lambda n: installed.get(n))
    pins = [("fastapi", "0.163.1"), ("httpx", "0.28.1"), ("jinja2", "3.1.6")]
    missing = [(n, v) for n, v in pins if start._installed_version(n) != v]
    assert missing == [("httpx", "0.28.1"), ("jinja2", "3.1.6")]
