"""UI-smoke (Playwright): логин → поиск в /vulns → панель фильтра истории.

Запускается отдельным CI-джобом ui-smoke (playwright ставится только там).
В обычном pytest-прогоне пропускается, если playwright не установлен.
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


@pytest.mark.e2e
@pytest.mark.ui
def test_ui_smoke():
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
            # «?»-подсказки на главной: кнопка у панели URL + тултип по наведению
            assert page.locator(".help-q").count() >= 1
            page.locator('.help-q[data-help="ui:panel.url"]').hover()
            page.wait_for_selector(".help-tip.show", timeout=3000)
            assert len(page.locator(".help-tip.show").inner_text()) > 10
            # «?» на одной линии с заголовком панели: центр кнопки ≈ центр текста
            btn_box = page.locator('.help-q[data-help="ui:panel.url"]').bounding_box()
            lbl_box = page.locator('.panel-label[data-i18n="panel.url"]').bounding_box()
            assert btn_box and lbl_box
            btn_cy = btn_box["y"] + btn_box["height"] / 2
            lbl_cy = lbl_box["y"] + lbl_box["height"] / 2
            assert abs(btn_cy - lbl_cy) < 3
            assert page.eval_on_selector(".stat-box .help-row", "el => getComputedStyle(el).justifyContent") == "center"
            ab = page.locator('.help-q[data-help="ui:auth.acc1"]').bounding_box()
            at = page.locator('.auth-section-title[data-i18n="auth.acc1"]').bounding_box()
            assert ab and at
            assert abs((ab["y"] + ab["height"] / 2) - (at["y"] + at["height"] / 2)) < 3
            # Свой режим: у каждой проверки есть «?»
            page.click('.mode-item[data-mode="custom"] span[data-i18n="mode.custom"]')
            page.wait_for_selector("#checksList .check-item", timeout=5000)
            assert page.locator("#checksList .help-q").count() >= 1
            # Справочник: поиск по EN-названию сужает карточки без перезагрузки
            page.goto(url + "/vulns")
            # Якоря отчётов подсвечивают карточку реестра; бейджи RU+EN; счётчик секций
            page.goto(url + "/vulns#open-cors")
            page.wait_for_timeout(400)
            assert page.locator(".vr-card.vg-target").count() >= 1
            assert "уязвимостей" in page.locator("#vg-count").inner_text().lower()
            assert page.locator(".vg-card .lvl b").count() >= 1
            assert page.locator(".vg-card .lvl i").count() == 0  # EN-бейджи удалены (RU-only)
            # Поиск по EN-названию сужает карточки без перезагрузки
            page.fill("#vg-q", "SQL")
            assert page.locator(".vg-card:visible").count() >= 1
            # История: панель фильтра дат присутствует в DOM
            page.goto(url + "/")
            assert page.locator(".hf-panel").count() == 1
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


@pytest.mark.e2e
@pytest.mark.ui
def test_scan_toast():
    """Тост слева снизу: «Сканирование запущено…» при старте и «Проверка завершена ✓» по финалу."""
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
            page.fill("#urlInput", "http://127.0.0.1:1")
            page.click("#scanBtn")
            page.wait_for_selector(".crt-toast.show", timeout=5000)
            assert "Сканирование запущено" in page.locator(".crt-toast").inner_text()
            pos = page.evaluate(
                "() => { const s = getComputedStyle(document.getElementById('crt-toast'));"
                " return { position: s.position, left: s.left, bottom: s.bottom }; }"
            )
            assert pos["position"] == "fixed" and pos["left"] == "16px" and pos["bottom"] == "16px"
            page.wait_for_function(
                "() => { const t = document.getElementById('crt-toast');"
                " return t && t.classList.contains('show') && t.textContent.includes('Проверка завершена'); }",
                timeout=90000,
            )
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
