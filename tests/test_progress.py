"""Счётчик запросов скана: бюджет пробрасывается в to_dict/status."""

from checks.base import RequestBudget
from scanner.tasks import ScanTask


def test_task_requests_counter():
    task = ScanTask("http://t", mode="quick")
    d = task.to_dict()
    assert d["requests_used"] == 0 and d["requests_max"] > 0
    task.budget = RequestBudget(1500)
    task.budget.take(7)
    d = task.to_dict()
    assert d["requests_used"] == 7 and d["requests_max"] == 1500
