"""UI (Playwright): проверка RU-only интерфейса."""
import os, socket, subprocess, sys, tempfile, time, urllib.request, pytest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close(); return port
@pytest.mark.e2e
@pytest.mark.ui
def test_ru_only_interface():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright
    port = _free_port(); url = f"http://127.0.0.1:{port}"
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False); db.close()
    env = dict(os.environ, SCANNER_DB_PATH=db.name, SCANNER_ADMIN_PASSWORD="admin", SCAN_RPS="0")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "web_app:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        ready = False
        for _ in range(80):
            try:
                with urllib.request.urlopen(url + "/healthz", timeout=1) as r:
                    if r.status == 200: ready = True; break
            except Exception: time.sleep(0.25)
        assert ready, "Server did not start"
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url + "/login")
            assert page.locator("#langToggle").count() == 0
            assert "ВХОД" in page.content() or "LOGIN" not in page.content()
            page.fill('input[name="username"]', "admin")
            page.fill('input[name="password"]', "admin")
            page.click('button[type="submit"]')
            page.wait_for_url("**/scanner")
            assert "СКАНЕР" in page.content()
            browser.close()
    finally:
        proc.terminate(); proc.wait()
