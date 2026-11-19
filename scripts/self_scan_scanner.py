"""Self-scan САМОГО сканера для CI: он должен быть чистым (gate по CRITICAL).

В отличие от self_scan.py (учебная цель, «так и задумано»), здесь мы сканируем
scanner-приложение как гость и падаем при любой CRITICAL-находке — регрессионная
защита самого инструмента. SARIF загружается в Security tab (category scanner-self).

Запуск: python scripts/self_scan_scanner.py --out scanner.sarif
"""

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_ready(url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="scanner.sarif")
    ap.add_argument("--mode", default="quick")
    args = ap.parse_args()

    from scanner.reporting import results_to_sarif
    from scanner.tasks import ScanTask, scan_engine

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    env = dict(os.environ, SCANNER_ALLOW_PRIVATE_TARGETS="1")
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
        if not _wait_ready(url):
            print("[scanner-self-scan] не удалось поднять сканер", file=sys.stderr)
            return 1
        task = ScanTask(url, mode=args.mode)
        asyncio.run(scan_engine(task))
        sarif = results_to_sarif(url, time.strftime("%Y-%m-%dT%H:%M:%S"), task.scan_results)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)
        critical = [r for r in task.scan_results if r.get("level") == "CRITICAL"]
        print(
            f"[scanner-self-scan] status={task.status} findings={len(task.scan_results)} "
            f"critical={len(critical)} -> {args.out}"
        )
        if critical:
            print("[scanner-self-scan] РЕГРЕССИЯ: сканер сам содержит CRITICAL-уязвимости", file=sys.stderr)
            return 1
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
