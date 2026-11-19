"""Единая точка входа: учебная цель + сканер одной командой.

Ставит зависимости СТРОГО по requirements.txt (с пинами), поднимает оба
сервиса, сам находит свободные порты и открывает браузер. Ctrl+C гасит оба.
"""
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
REQ_FILE = os.path.join(REPO_ROOT, "requirements.txt")
os.chdir(REPO_ROOT)
sys.path.insert(0, REPO_ROOT)


def _parse_pins(text):
    """name==version из requirements.txt (комментарии/-r/extras/маркеры игнорируем)."""
    pins = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([^\s;]+)", line)
        if m:
            pins.append((m.group(1), m.group(3)))
    return pins


def _installed_version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:
        return None


def _ensure_pip():
    try:
        import pip  # noqa: F401
    except Exception:
        subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])


def ensure_dependencies():
    _ensure_pip()
    with open(REQ_FILE, encoding="utf-8") as f:
        pins = _parse_pins(f.read())
    missing = [(n, v) for n, v in pins if _installed_version(n) != v]
    if not missing:
        return
    print(f"[start] доустанавливаю {len(missing)} пакетов строго по requirements.txt: "
          + ", ".join(f"{n}=={v}" for n, v in missing))
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", REQ_FILE])
    try:
        import weasyprint  # noqa: F401
    except Exception:
        print("[start] ВНИМАНИЕ: WeasyPrint не импортируется (нужны системные pango/GTK). "
              "PDF-экспорт будет недоступен, остальные отчёты работают. В Docker всё вшито.")


def _free_port(preferred):
    for port in range(preferred, preferred + 50):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("не нашёл свободный порт")


def main():
    args = sys.argv[1:]
    if "--skip-install" not in args:
        ensure_dependencies()

    import uvicorn
    from main import app as target_app
    from scanner.app import app as scanner_app

    api_port = _free_port(int(os.environ.get("API_PORT", "8000")))
    web_port = _free_port(int(os.environ.get("SCANNER_PORT", "8001")))
    api_host = os.environ.get("API_HOST", "127.0.0.1")
    web_host = os.environ.get("SCANNER_HOST", "127.0.0.1")

    servers = [
        uvicorn.Server(uvicorn.Config(target_app, host=api_host, port=api_port, log_level="warning")),
        uvicorn.Server(uvicorn.Config(scanner_app, host=web_host, port=web_port, log_level="warning")),
    ]
    threads = [threading.Thread(target=s.run, daemon=True) for s in servers]
    for t in threads:
        t.start()
    for s in servers:
        for _ in range(100):
            if s.started:
                break
            time.sleep(0.1)

    url = f"http://{'127.0.0.1' if web_host == '0.0.0.0' else web_host}:{web_port}"
    print("\n\033[32m=== DevSecOps Scanner запущен ===\033[0m")
    print(f"  Цель (уязвимое API): http://127.0.0.1:{api_port}  (Swagger: /docs)")
    print(f"  Сканер:              {url}")
    print("  Вход: admin / admin  (пароль можно задать через SCANNER_ADMIN_PASSWORD)")
    print("  Ctrl+C — остановить оба сервиса\n")
    if "--no-browser" not in args:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[start] останавливаю сервисы...")
        for s in servers:
            s.should_exit = True
        for t in threads:
            t.join(timeout=5)


if __name__ == "__main__":
    main()
