"""Пресеты дат в static/history_filter.js считаются по МСК, а не по TZ браузера.

Тест гоняет реальные хелперы из файла в node с подменённым «сейчас» и разными TZ
процесса: результат обязан совпадать с расчётом по Москве (UTC+3).
Пропускается, если node не установлен (в CI он есть — там же гоняется node --check).
"""

import datetime
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS_PATH = os.path.join(ROOT, "static", "history_filter.js")
NODE = shutil.which("node") or ("/opt/nodebin/node" if os.path.exists("/opt/nodebin/node") else None)

pytestmark = pytest.mark.skipif(NODE is None, reason="node не установлен")


def _helpers() -> str:
    src = open(JS_PATH, encoding="utf-8").read()
    m = re.search(r"const MSK_OFFSET_MS.*?const mskDaysAgo = n => \{.*?\n  \};", src, re.S)
    assert m, "в history_filter.js не найдены МСК-хелперы пресетов"
    return m.group(0)


def _run(now_iso: str, tz: str) -> dict:
    now = datetime.datetime.fromisoformat(now_iso).replace(tzinfo=datetime.timezone.utc)
    script = (
        "const RealDate = Date;\n"
        f"const fixed = {int(now.timestamp() * 1000)};\n"
        "class FakeDate extends RealDate {\n"
        "  constructor(...args) { if (args.length === 0) super(fixed); else super(...args); }\n"
        "  static now() { return fixed; }\n"
        "}\n"
        "globalThis.Date = FakeDate;\n" + _helpers() + "\n"
        "console.log(JSON.stringify({today: mskDay(), d1: mskDaysAgo(1), d7: mskDaysAgo(7), d30: mskDaysAgo(30)}));\n"
    )
    env = {**os.environ, "TZ": tz}
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, env=env, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _expected(now_iso: str) -> dict:
    now = datetime.datetime.fromisoformat(now_iso).replace(tzinfo=datetime.timezone.utc)
    msk = now.astimezone(datetime.timezone(datetime.timedelta(hours=3)))
    day = msk.date()
    return {
        "today": day.isoformat(),
        "d1": day.isoformat(),
        "d7": (day - datetime.timedelta(days=6)).isoformat(),
        "d30": (day - datetime.timedelta(days=29)).isoformat(),
    }


@pytest.mark.parametrize(
    "now_iso",
    [
        "2026-11-25T22:30:00",  # 01:30 МСК следующего дня
        "2026-11-25T20:59:59",  # 23:59:59 МСК того же дня
        "2026-12-31T23:30:00",  # переход года
        "2028-02-28T22:30:00",  # високосный год
        "2026-03-01T21:30:00",  # переход месяца
    ],
)
@pytest.mark.parametrize("tz", ["UTC", "America/Los_Angeles", "Asia/Kamchatka"])
def test_presets_are_msk_and_tz_independent(now_iso, tz):
    assert _run(now_iso, tz) == _expected(now_iso)


def test_no_local_timezone_apis_left():
    src = open(JS_PATH, encoding="utf-8").read()
    for forbidden in ("setDate(", "getDate(", "toLocaleString", "toLocaleDateString", "getTimezoneOffset"):
        assert forbidden not in src, f"{forbidden} — локальная TZ снова в пресетах"
    assert "UTC" in src  # МСК описан через UTC+3
