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


def _active_package_lines(path):
    """Только активные (не комментарии) строки пакетов из requirements-файла."""
    txt = open(os.path.join(ROOT, path), encoding="utf-8").read()
    out = []
    for line in txt.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        out.append(stripped)
    return out


def test_requirements_all_hashed():
    blocks = _blocks("requirements.txt")
    assert blocks
    for b in blocks:
        assert "--hash=sha256:" in b, b


def test_requirements_direct_pins_kept():
    # Прямые зависимости запинены (==X.Y.Z); конкретные версии НЕ хардкодим.
    # Хардкод номеров воевал с Dependabot: любой bump ломал этот тест (PR #58).
    # Нужный инвариант — «прямой пин с версией», а не «конкретная версия»;
    # целостность хешей проверяет test_requirements_all_hashed.
    txt = open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8").read()
    for pkg in ("fastapi", "httpx", "pydantic", "uvicorn[standard]"):
        assert re.search(rf"^{re.escape(pkg)}==\d+\.\d+", txt, re.M), f"{pkg} должен быть запинен через =="
    # weasyprint полностью удалён (PDF теперь через Playwright)
    assert "weasyprint==" not in txt, "weasyprint removed: PDF now uses Playwright"
    # playwright ставится отдельным шагом (start.py + Dockerfile), не через
    # requirements.txt (--require-hashes требует хеш для каждого пакета,
    # а у playwright sha256 разные на каждой платформе).
    # Проверяем, что в файле нет АКТИВНОЙ строки-зависимости playwright
    # (упоминание в комментариях — нормально).
    for line in _active_package_lines("requirements.txt"):
        assert not line.startswith("playwright"), (
            f"playwright must NOT be a direct dependency in requirements.txt "
            f"(installed separately in start.py/Dockerfile). Found: {line!r}"
        )


def test_playwright_version_pinned_in_start_py():
    """playwright==X.Y.Z должен быть зафиксирован в start.py."""
    txt = open(os.path.join(ROOT, "start.py"), encoding="utf-8").read()
    # Пин версии в виде PLAYWRIGHT_VERSION = "X.Y.Z"
    assert re.search(r"PLAYWRIGHT_VERSION\s*=\s*['\"]\d+\.\d+\.\d+['\"]", txt), (
        "start.py must define PLAYWRIGHT_VERSION = 'X.Y.Z'"
    )
    # Команда установки Chromium: список аргументов ["playwright", "install", "chromium"]
    assert re.search(
        r'["\']playwright["\']\s*,\s*["\']install["\']\s*,\s*["\']chromium["\']',
        txt,
    ), "start.py must run: [sys.executable, '-m', 'playwright', 'install', 'chromium']"


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
    # httpx2 (преемник httpx, мейнтейнится Pydantic) остаётся запиненным в dev.
    txt = open(os.path.join(ROOT, "requirements-dev.txt"), encoding="utf-8").read()
    assert re.search(r"^httpx2==\d+\.\d+", txt, re.M), "httpx2 должен остаться в requirements-dev.txt"
