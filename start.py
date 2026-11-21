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
        return
    # pip < 21 не понимает manylinux-теги свежих wheels и молча скатывается
    # на сборку из исходников — обновляем (best-effort).
    try:
        major = int(pip.__version__.split(".")[0])
    except Exception:
        major = 0
    if major < 21:
        subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", "pip>=23"])


def _pip_install_cmd(*extra):
    return [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *extra, "-r", REQ_FILE]


def _run_pip(cmd):
    """pip с перехватом вывода: диагностика без простыни gcc-ошибок в консоли."""
    return subprocess.run(cmd, capture_output=True, text=True)


def _devel_packages_hint():
    """Команда установки заголовков Python/компилятора под дистрибутив."""
    distro = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("ID="):
                    distro = line.strip().split("=", 1)[1].strip('"')
                    break
    except OSError:
        pass
    if distro in ("fedora", "rhel", "centos", "rocky", "almalinux", "ol"):
        return "sudo dnf install python3-devel gcc libffi-devel libjpeg-turbo-devel zlib-devel"
    if distro in ("debian", "ubuntu", "linuxmint", "pop"):
        return "sudo apt-get install python3-dev build-essential libffi-dev libjpeg-dev zlib1g-dev"
    if distro == "alpine":
        return "sudo apk add python3-dev gcc musl-dev libffi-dev jpeg-dev zlib-dev"
    return "sudo apt-get install python3-dev build-essential libffi-dev  # или sudo dnf install python3-devel gcc"


def ensure_dependencies():
    _ensure_pip()
    with open(REQ_FILE, encoding="utf-8") as f:
        pins = _parse_pins(f.read())
    missing = [(n, v) for n, v in pins if _installed_version(n) != v]
    if not missing:
        return
    print(
        f"[start] доустанавливаю {len(missing)} пакетов строго по requirements.txt: "
        + ", ".join(f"{n}=={v}" for n, v in missing)
    )
    # 1) Только готовые wheels — компиляция не нужна (python3-devel/gcc не требуются).
    #    Хеши покрывают Linux x86_64/aarch64, Python 3.10–3.13.
    res = _run_pip(_pip_install_cmd("--only-binary", ":all:"))
    if res.returncode != 0:
        # 2) Fallback: сборка из исходников (нужны gcc и заголовки Python).
        print("[start] wheels не подошли — пробую сборку из исходников (может занять несколько минут)...")
        res = _run_pip(_pip_install_cmd())
    if res.returncode != 0:
        out = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
        print("\n".join(out.splitlines()[-20:]))
        print("\n\033[31m[start] Не удалось установить зависимости.\033[0m")
        if "Python.h" in out:
            print("[start] Не хватает заголовков Python (Python.h). Установите их и перезапустите start.py:")
        else:
            print("[start] Готовые wheels захэшированы для Linux (x86_64/aarch64), Python 3.10–3.13.")
            print("[start] Варианты: Python 3.12/3.13, Docker (docker build -t curseach .) или компилятор:")
        print("    " + _devel_packages_hint())
        raise SystemExit(1)
    try:
        import weasyprint  # noqa: F401
    except Exception:
        print(
            "[start] ВНИМАНИЕ: WeasyPrint не импортируется (нужны системные pango/GTK). "
            "PDF-экспорт будет недоступен, остальные отчёты работают. В Docker всё вшито."
        )

def _pick_ports(api_preferred, web_preferred):
    """Два РАЗНЫХ свободных порта: цель и сканер не должны занять один и тот же."""
    api_port = _free_port(api_preferred)
    web_port = _free_port(web_preferred)
    if web_port == api_port:
        web_port = _free_port(web_port + 1)
    return api_port, web_port


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

    api_port, web_port = _pick_ports(
        int(os.environ.get("API_PORT", "8000")), int(os.environ.get("SCANNER_PORT", "8001"))
    )
    api_host = os.environ.get("API_HOST", "127.0.0.1")
    web_host = os.environ.get("SCANNER_HOST", "127.0.0.1")
    if web_host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("SCANNER_ADMIN_PASSWORD"):
        print("\n\033[31m[ВНИМАНИЕ] Сканер слушает публичный интерфейс с паролем по умолчанию admin/admin!\033[0m")
        print("  Задайте SCANNER_ADMIN_PASSWORD и SCANNER_GUEST_PASSWORD перед публичным деплоем.\n")

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
