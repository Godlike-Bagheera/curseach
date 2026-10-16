"""
Launcher: запускает уязвимое API и DevSecOps Scanner одной командой.
- Автоматически устанавливает зависимости
- Автоматически находит свободные порты, если стандартные заняты
- Повторяет попытку запуска, если порт был перехвачен между проверкой и стартом
- Показывает цветные логи и корректно останавливает всё по Ctrl+C
- Работает из любой рабочей директории (делает chdir в папку скрипта)

Примечание: Playwright/Chromium больше не нужны — экспорт PDF выполнен
на клиентскую печать браузера (кнопка «Скачать PDF» -> window.print()).
"""

import subprocess
import sys
import time
import signal
import webbrowser
import threading
import os
import socket
import importlib.util

# ---------- Конфигурация ----------
API_HOST = os.environ.get("API_HOST", "127.0.0.1")
API_PORT_DEFAULT = 8000
SCANNER_HOST = os.environ.get("SCANNER_HOST", "127.0.0.1")
SCANNER_PORT_DEFAULT = 8001

START_MAX_RETRIES = 5

REQUIRED_PACKAGES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn[standard]",
    "httpx": "httpx",
    "jinja2": "jinja2",
    "pydantic": "pydantic",
    "multipart": "python-multipart",
    "openpyxl": "openpyxl",
    "weasyprint": "weasyprint",
}

# ---------- Цветной вывод ----------
if os.name == "nt":
    os.system("")

C_RESET = "\033[0m"
C_GREEN = "\033[92m"
C_BLUE = "\033[94m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"


def banner():
    print(f"""{C_CYAN}{C_BOLD}
╔══════════════════════════════════════════════════════════╗
║        🔐  DevSecOps API Security Scanner                ║
║        Однокомандный запуск всего проекта                ║
╚══════════════════════════════════════════════════════════╝
{C_RESET}""")


# ---------- Проверка и установка зависимостей ----------
def is_package_installed(import_name: str) -> bool:
    return importlib.util.find_spec(import_name) is not None


def _pip_available():
    """Проверяет, что в текущем интерпретаторе есть pip."""
    if importlib.util.find_spec("pip"):
        return True
    # Попытка self-heal (PEP 538/454 окружения без pip)
    try:
        r = subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"],
                           capture_output=True, text=True)
        if r.returncode == 0 and importlib.util.find_spec("pip"):
            return True
    except Exception:
        pass
    return False


def install_packages(pip_names):
    print(f"{C_BLUE}[*] Установка зависимостей: {', '.join(pip_names)}{C_RESET}")
    if not _pip_available():
        print(f"{C_RED}[!] В интерпретаторе {sys.executable} нет модуля pip.{C_RESET}")
        print("    Запустите через настроенное окружение:")
        print("      python3 -m venv .venv && . .venv/bin/activate && "
              "pip install -r requirements.txt")
        print("    (в Codespaces достаточно просто `python start.py` — "
              "зависимости ставятся при сборке контейнера)")
        sys.exit(1)
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install"] + pip_names,
            check=False,
        )
        if result.returncode != 0:
            print(f"{C_RED}[!] Не удалось установить зависимости.{C_RESET}")
            print(f"{C_YELLOW}    Попробуйте вручную:{C_RESET}")
            print(f"    pip install {' '.join(pip_names)}")
            sys.exit(1)
    except Exception as e:
        print(f"{C_RED}[!] Ошибка при установке: {e}{C_RESET}")
        sys.exit(1)


def ensure_dependencies():
    missing = [
        pip_name for import_name, pip_name in REQUIRED_PACKAGES.items()
        if not is_package_installed(import_name)
    ]
    if not missing:
        print(f"{C_GREEN}[✓]{C_RESET} Все зависимости найдены")
        return
    print(f"{C_YELLOW}[!] Отсутствуют пакеты: {', '.join(missing)}{C_RESET}")
    print(f"{C_BLUE}[*] Устанавливаю автоматически...{C_RESET}\n")
    install_packages(missing)
    still = [
        name for import_name, name in REQUIRED_PACKAGES.items()
        if not is_package_installed(import_name)
    ]
    if still:
        print(f"{C_RED}[!] Всё ещё не установлены: {', '.join(still)}{C_RESET}")
        sys.exit(1)
    print(f"{C_GREEN}[✓]{C_RESET} Зависимости успешно установлены")


# ---------- Порты ----------
def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_free_port(host: str, start_port: int, max_tries: int = 50) -> int:
    for offset in range(max_tries):
        candidate = start_port + offset
        if is_port_free(host, candidate):
            return candidate
    raise RuntimeError(f"Не удалось найти свободный порт начиная с {start_port}")


def resolve_port(host: str, default_port: int, name: str, quiet: bool = False) -> int:
    if is_port_free(host, default_port):
        return default_port

    if not quiet:
        print(f"{C_YELLOW}[!] Порт {default_port} ({name}) занят.{C_RESET}")
    try:
        new_port = find_free_port(host, default_port + 1)
    except RuntimeError as e:
        print(f"{C_RED}[!] {e}{C_RESET}")
        sys.exit(1)

    if not quiet:
        print(f"{C_GREEN}[✓]{C_RESET} Использую свободный порт: {C_CYAN}{new_port}{C_RESET}")
    return new_port


# ---------- Запуск процессов ----------
def start_process(module, port, host):
    cmd = [
        sys.executable, "-m", "uvicorn",
        f"{module}:app",
        "--host", host,
        "--port", str(port),
        "--log-level", "warning",
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=os.environ.copy(),
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )


def start_process_with_retry(module, host, default_port, name):
    last_port = default_port
    for attempt in range(START_MAX_RETRIES):
        port = resolve_port(host, last_port, name, quiet=(attempt > 0))
        proc = start_process(module, port, host)
        time.sleep(1.5)
        if proc.poll() is None:
            return port, proc

        print(f"{C_YELLOW}[!] {name} не поднялся на порту {port}, пробую следующий...{C_RESET}")
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        last_port = port + 1

    print(f"{C_RED}[!] Не удалось запустить {name} за {START_MAX_RETRIES} попыток.{C_RESET}")
    sys.exit(1)


def stream_logs(proc, prefix, color):
    for line in iter(proc.stdout.readline, ""):
        if line.strip():
            print(f"{color}[{prefix}]{C_RESET} {line.rstrip()}")


def open_browser_later(url, delay=2.5):
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


# ---------- Точка входа ----------
def main():
    # КРИТИЧНО: работаем из папки скрипта, а не из cwd вызывающего.
    # Иначе uvicorn не найдёт templates/ и static/ при запуске
    # из другой рабочей директории.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    banner()
    ensure_dependencies()

    print(f"\n{C_BLUE}[*] Запуск уязвимого API...{C_RESET}")
    api_port, api_proc = start_process_with_retry("main", API_HOST, API_PORT_DEFAULT, "API")
    threading.Thread(
        target=stream_logs,
        args=(api_proc, "API", C_YELLOW),
        daemon=True,
    ).start()

    print(f"{C_GREEN}[✓]{C_RESET} API запущен:      {C_CYAN}http://{API_HOST}:{api_port}{C_RESET}")
    print(f"{C_GREEN}[✓]{C_RESET} Swagger UI:       {C_CYAN}http://{API_HOST}:{api_port}/docs{C_RESET}")

    print(f"\n{C_BLUE}[*] Запуск веб-интерфейса сканера...{C_RESET}")
    scanner_port, scanner_proc = start_process_with_retry(
        "web_app", SCANNER_HOST, SCANNER_PORT_DEFAULT, "Scanner"
    )
    threading.Thread(
        target=stream_logs,
        args=(scanner_proc, "SCAN", C_GREEN),
        daemon=True,
    ).start()

    print(f"{C_GREEN}[✓]{C_RESET} Сканер запущен:   {C_CYAN}http://{SCANNER_HOST}:{scanner_port}{C_RESET}")

    print(f"""
{C_BOLD}{C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C_RESET}
{C_BOLD}  🎯  Всё готово! Открываю браузер...{C_RESET}
{C_BOLD}{C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C_RESET}

  API (цель):    {C_CYAN}http://{API_HOST}:{api_port}{C_RESET}
  Сканер:        {C_CYAN}http://{SCANNER_HOST}:{scanner_port}{C_RESET}

  Для остановки нажмите {C_BOLD}Ctrl + C{C_RESET}
""")

    open_browser_later(f"http://{SCANNER_HOST}:{scanner_port}")

    def shutdown(signum=None, frame=None):
        print(f"\n{C_YELLOW}[*] Остановка серверов...{C_RESET}")
        for p in (api_proc, scanner_proc):
            try:
                p.terminate()
            except Exception:
                pass
        for p in (api_proc, scanner_proc):
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print(f"{C_GREEN}[✓]{C_RESET} Все процессы остановлены. До связи!")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(0.5)
            if api_proc.poll() is not None:
                print(f"{C_RED}[!] API неожиданно завершился.{C_RESET}")
                shutdown()
            if scanner_proc.poll() is not None:
                print(f"{C_RED}[!] Сканер неожиданно завершился.{C_RESET}")
                shutdown()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()