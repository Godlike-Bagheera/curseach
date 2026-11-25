"""Self-scan для CI: поднимает учебную цель, сканирует её и пишет SARIF.

Запуск: python scripts/self_scan.py --out report.sarif
Результат загружается в GitHub Security tab (workflow security-scan.yml).
"""

import argparse
import asyncio
import datetime
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
            with urllib.request.urlopen(url + "/", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="report.sarif")
    ap.add_argument("--seed", type=int, default=5)
    ap.add_argument("--mode", default="full")
    args = ap.parse_args()

    from scanner.reporting import results_to_sarif
    from scanner.tasks import AccountConfig, ScanTask, scan_engine

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "main:app",
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
    )
    try:
        if not _wait_ready(url):
            print("[self-scan] не удалось поднять цель", file=sys.stderr)
            return 1
        task = ScanTask(
            url,
            mode=args.mode,
            seed=args.seed,
            account1=AccountConfig(username="alice", password="alice123"),
            account2=AccountConfig(username="bob", password="bob123"),
        )
        asyncio.run(scan_engine(task))
        # Гейт регрессии детектора: ключевые типы обязаны находиться на учебной цели.
        detected = {f.get("type") for f in task.scan_results}
        expected = {"SQL Injection", "Broken Access Control", "JWT alg=none"}
        missing = expected - detected
        if missing:
            print(
                f"[self-scan] РЕГРЕССИЯ детектора: не найдены {sorted(missing)}; обнаружено: {sorted(detected)}",
                file=sys.stderr,
            )
            return 1
        sarif = results_to_sarif(url, datetime.datetime.now(datetime.timezone.utc).isoformat(), task.scan_results)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)
        print(f"[self-scan] status={task.status} findings={len(task.scan_results)} score={task.score} -> {args.out}")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
