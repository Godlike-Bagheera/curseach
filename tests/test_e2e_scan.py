"""E2E: поднимаем учебную цель (main.py) и сканируем её движком с фиксированным seed."""

import asyncio
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = 5  # профиль со всеми основными уязвимостями (детерминирован)

pytestmark = [pytest.mark.slow, pytest.mark.e2e]


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def target_url():
    port = _free_port()
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
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        ready = False
        for _ in range(80):
            try:
                with urllib.request.urlopen(url + "/", timeout=1) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.25)
        if not ready:
            pytest.skip("не удалось поднять учебную цель")
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def test_seeded_quick_scan_finds_known_vulns(target_url):
    from scanner.tasks import AccountConfig, ScanTask, scan_engine

    task = ScanTask(
        target_url,
        mode="quick",
        seed=SEED,
        account1=AccountConfig(username="alice", password="alice123"),
        account2=AccountConfig(username="bob", password="bob123"),
    )
    asyncio.run(scan_engine(task))
    assert task.status == "completed", task.error
    types = {f["type"] for f in task.scan_results}
    assert "SQL Injection" in types
    assert "Broken Access Control" in types
    assert "JWT alg=none" in types
    # evidence, confidence, CWE/OWASP и дедупликация
    assert any(f.get("evidence") for f in task.scan_results)
    assert all(f.get("confidence") for f in task.scan_results)
    sqli = [f for f in task.scan_results if f["type"] == "SQL Injection"]
    assert all((f.get("details") or {}).get("cwe") for f in sqli)
    keys = [(f["type"], f["endpoint"], f.get("param", ""), f.get("method", "")) for f in task.scan_results]
    assert len(keys) == len(set(keys)), "дедупликация не сработала"
    # Бюджет: per-check квот нет, общий счётчик и статистика по проверкам ведутся,
    # обязательные детекции (выше) не потеряны.
    assert task.budget is not None
    assert task.budget.per_check_cap is None
    assert task.budget.per_check, "запросы не посчитаны по проверкам"
    assert sum(task.budget.per_check.values()) <= task.budget.used
    # Статистика покрытия доступна в задаче и в to_dict.
    assert task.endpoints_count > 0 and task.surfaces_count > 0
    d = task.to_dict()
    assert d["endpoints_count"] == task.endpoints_count
    assert d["surfaces_count"] == task.surfaces_count
    assert d["requests_used"] == task.budget.used


def test_scan_cancellation(target_url):
    from scanner.tasks import AccountConfig, ScanTask, scan_engine

    task = ScanTask(target_url, mode="full", seed=SEED, account1=AccountConfig(username="alice", password="alice123"))
    task.cancel_event.set()  # отмена до старта
    asyncio.run(scan_engine(task))
    assert task.status == "cancelled"


def test_small_budget_keeps_mandatory_detections(target_url, monkeypatch):
    """Маленький общий бюджет: обязательные детекции не теряются."""
    import scanner.tasks as st
    from scanner.tasks import AccountConfig, ScanTask, scan_engine

    monkeypatch.setattr(st, "SCAN_MAX_REQUESTS", 400)
    task = ScanTask(
        target_url,
        mode="quick",
        seed=SEED,
        account1=AccountConfig(username="alice", password="alice123"),
        account2=AccountConfig(username="bob", password="bob123"),
    )
    asyncio.run(scan_engine(task))
    assert task.status == "completed", task.error
    types = {f["type"] for f in task.scan_results}
    assert "SQL Injection" in types
    assert "Broken Access Control" in types
    assert "JWT alg=none" in types
