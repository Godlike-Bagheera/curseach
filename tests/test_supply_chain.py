"""Supply-chain: digest base-image + pip --require-hashes (ROADMAP: прочее)."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _blocks(path):
    txt = open(os.path.join(ROOT, path), encoding="utf-8").read().replace("\\\n", " ")
    out = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r"):
            continue
        out.append(line)
    return out


def test_requirements_all_hashed():
    blocks = _blocks("requirements.txt")
    assert blocks
    for b in blocks:
        assert "--hash=sha256:" in b, b


def test_requirements_direct_pins_kept():
    txt = open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8").read()
    for pin in (
        "fastapi==0.163.1",
        "httpx==0.28.1",
        "pydantic==2.14.3",
        "weasyprint==70.0",
        "uvicorn[standard]==0.54.0",
    ):
        assert pin in txt


def test_dev_requirements_all_hashed():
    blocks = _blocks("requirements-dev.txt")
    assert blocks
    for b in blocks:
        assert "--hash=sha256:" in b, b


def test_dev_includes_runtime():
    txt = open(os.path.join(ROOT, "requirements-dev.txt"), encoding="utf-8").read()
    assert "-r requirements.txt" in txt


def test_dockerfile_digest_and_require_hashes():
    txt = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
    assert re.search(r"FROM python:3\.12-slim@sha256:[0-9a-f]{64}", txt)
    assert "--require-hashes" in txt


def test_httpx2_trusted_kept():
    txt = open(os.path.join(ROOT, "requirements-dev.txt"), encoding="utf-8").read()
    assert "httpx2==2.16.2" in txt
