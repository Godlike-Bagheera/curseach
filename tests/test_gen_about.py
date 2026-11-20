"""Генерация about.html из единого источника проверок (ROADMAP: прочее)."""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import gen_about  # noqa: E402

from checks import CHECK_METADATA  # noqa: E402
from scanner.vuln_guide import build_registry  # noqa: E402


def _about():
    return open(os.path.join(ROOT, "about.html"), encoding="utf-8").read()


def test_markers_present():
    txt = _about()
    assert gen_about.START in txt and gen_about.END in txt


def test_render_contains_all_checks():
    reg = build_registry()
    block = gen_about.render_checks(reg)
    for cid in CHECK_METADATA:
        assert cid in block
    assert f"{len(CHECK_METADATA)} проверок" in block


def test_about_in_sync():
    r = subprocess.run([sys.executable, "scripts/gen_about.py", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_apply_idempotent():
    txt = _about()
    block = gen_about.render_checks(build_registry())
    assert gen_about.apply(txt, block) == txt


def test_drift_detected():
    txt = _about()
    block = gen_about.render_checks(build_registry())
    broken = re.sub(r"<strong>\d+ проверок</strong>", "<strong>999 проверок</strong>", txt, count=1)
    assert broken != txt
    assert gen_about.apply(broken, block) != broken
