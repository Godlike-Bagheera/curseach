"""Юнит-тесты requirements-driven бутстрапа start.py."""

from types import SimpleNamespace

import pytest

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


def test_install_prefers_wheels(monkeypatch):
    monkeypatch.setattr(start, "_ensure_pip", lambda: None)
    monkeypatch.setattr(start, "_installed_version", lambda n: None)
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(start, "_run_pip", fake_run)
    start.ensure_dependencies()
    assert len(calls) == 1
    assert "--only-binary" in calls[0] and ":all:" in calls[0]


def test_install_falls_back_to_source(monkeypatch):
    monkeypatch.setattr(start, "_ensure_pip", lambda: None)
    monkeypatch.setattr(start, "_installed_version", lambda n: None)
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return SimpleNamespace(returncode=1 if len(calls) == 1 else 0, stdout="", stderr="")

    monkeypatch.setattr(start, "_run_pip", fake_run)
    start.ensure_dependencies()
    assert len(calls) == 2
    assert "--only-binary" not in calls[1]


def test_install_failure_prints_devel_hint(monkeypatch, capsys):
    monkeypatch.setattr(start, "_ensure_pip", lambda: None)
    monkeypatch.setattr(start, "_installed_version", lambda n: None)
    monkeypatch.setattr(
        start,
        "_run_pip",
        lambda cmd: SimpleNamespace(returncode=1, stdout="", stderr="Python.h: Нет такого файла или каталога"),
    )
    with pytest.raises(SystemExit):
        start.ensure_dependencies()
    out = capsys.readouterr().out
    assert "python3-dev" in out or "python3-devel" in out
