"""UI-smoke с реальным сканом: quick-скан учебной цели, счётчик запросов, история, CSP без ошибок.

Запускается CI-джобом ui-smoke (playwright ставится только там). В обычном pytest
пропускается, если playwright не установлен.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait(url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


@pytest.mark.e2e
@pytest.mark.ui
def test_ui_real_scan():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    tport, sport = _free_port(), _free_port()
    target = f"http://127.0.0.1:{tport}"
    scanner = f"http://127.0.0.1:{sport}"
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db.close()
    tproc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(tport),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    senv = dict(
        os.environ,
        SCANNER_DB_PATH=db.name,
        SCANNER_ADMIN_PASSWORD="admin",
        SCANNER_ALLOW_PRIVATE_TARGETS="1",
        SCAN_RPS="0",
    )
    sproc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "web_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(sport),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=senv,
    )
    try:
        if not _wait(target + "/") or not _wait(scanner + "/healthz"):
            pytest.skip("не удалось поднять цель/сканер")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            console_errors = []
            page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: console_errors.append(str(e)))

            page.goto(scanner + "/login")
            page.fill("#username", "admin")
            page.fill("#password", "admin")
            page.click('button[type="submit"]')
            page.wait_for_url(scanner + "/", timeout=10000)

            page.fill("#urlInput", target)
            page.click('.mode-item[data-mode="quick"]')
            page.click("#scanBtn")
            page.wait_for_function("() => !document.getElementById('htmlBtn').disabled", timeout=120000)
            assert page.text_content("#statusValue").strip() == "ГОТОВО"
            assert "ЗАПРОСОВ" in page.text_content("#progressRequests")

            page.goto(scanner + "/")
            page.click('.tab-btn[data-tab="history"]')
            page.wait_for_selector(".history-table tbody tr", timeout=10000)
            browser.close()

            csp_bad = [
                e for e in console_errors if "Refused to" in e or "Content-Security-Policy" in e or "violates" in e
            ]
            assert not csp_bad, f"CSP-ошибки в консоли: {csp_bad}"
    finally:
        for pr in (sproc, tproc):
            pr.terminate()
            try:
                pr.wait(timeout=5)
            except Exception:
                pr.kill()
