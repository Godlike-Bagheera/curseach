"""UI (Playwright): интерфейс только на русском, переключателя языка нет."""

import os
import re
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


@pytest.mark.e2e
@pytest.mark.ui
def test_ru_only_ui():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db.close()
    env = dict(os.environ, SCANNER_DB_PATH=db.name, SCANNER_ADMIN_PASSWORD="admin", SCAN_RPS="0")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "web_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        ready = False
        for _ in range(80):
            try:
                with urllib.request.urlopen(url + "/healthz", timeout=1) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.25)
        if not ready:
            pytest.skip("не удалось поднять сканер")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url + "/login")
            assert page.locator("#langToggle").count() == 0
            assert "ВХОД" in page.locator("h1").first.inner_text()
            assert page.evaluate("document.documentElement.lang") == "ru"
            page.fill("#username", "admin")
            page.fill("#password", "admin")
            page.click('button[type="submit"]')
            page.wait_for_url(url + "/", timeout=10000)
            page.wait_for_selector("#loading-screen", state="detached", timeout=15000)
            assert page.locator("#langToggle").count() == 0
            assert "СКАНЕР" in page.locator("h1").first.inner_text()
            assert page.evaluate("document.documentElement.lang") == "ru"
            page.locator('.help-q[data-help="ui:panel.url"]').hover()
            page.wait_for_selector(".help-tip.show", timeout=3000)
            assert re.search(r"[А-Яа-яЁё]", page.locator(".help-tip.show").inner_text())
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
