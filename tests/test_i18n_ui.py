"""UI (Playwright): переключатель EN/RU меняет подписи и сохраняет выбор."""

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


@pytest.mark.e2e
@pytest.mark.ui
def test_i18n_toggle():
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
            page.fill("#username", "admin")
            page.fill("#password", "admin")
            page.click('button[type="submit"]')
            page.wait_for_url(url + "/", timeout=10000)
            page.wait_for_selector("#loading-screen", state="detached", timeout=15000)
            h1 = page.locator("h1").first
            assert "СКАНЕР" in h1.inner_text()
            page.click("#langToggle")
            assert "SCANNER" in h1.inner_text()
            assert page.evaluate("localStorage.getItem('curseach.lang')") == "en"
            page.click("#langToggle")
            assert "СКАНЕР" in h1.inner_text()
            assert page.evaluate("localStorage.getItem('curseach.lang')") == "ru"
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
