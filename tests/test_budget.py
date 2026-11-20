"""Per-check квоты бюджета запросов (ROADMAP: бюджет и покрытие)."""

from checks.base import _CHECK_NAME, RequestBudget


def test_budget_without_cap_backward_compatible():
    b = RequestBudget(5)
    assert b.per_check_cap is None
    assert all(b.take() for _ in range(5))
    assert b.take() is False
    assert b.exhausted is True
    assert b.used == 5


def test_per_check_cap_limits_single_check():
    b = RequestBudget(100, per_check_cap=3)
    tok = _CHECK_NAME.set("check_sqli")
    try:
        assert b.take() and b.take() and b.take()
        assert b.take() is False  # квота проверки исчерпана
        assert b.exhausted is False  # общий бюджет ещё жив
        assert b.used == 3
        assert b.per_check["check_sqli"] == 3
        assert "check_sqli" in b.per_check_capped
    finally:
        _CHECK_NAME.reset(tok)


def test_per_check_cap_is_per_check():
    b = RequestBudget(100, per_check_cap=2)
    tok = _CHECK_NAME.set("check_a")
    try:
        assert b.take() and b.take()
        assert b.take() is False
    finally:
        _CHECK_NAME.reset(tok)
    tok = _CHECK_NAME.set("check_b")
    try:
        assert b.take() and b.take()  # у другой проверки своя квота
        assert b.take() is False
    finally:
        _CHECK_NAME.reset(tok)
    assert b.used == 4
    assert b.per_check == {"check_a": 2, "check_b": 2}


def test_no_check_name_ignores_cap():
    b = RequestBudget(100, per_check_cap=1)
    assert b.take() and b.take()  # вне проверки квота не применяется
    assert b.used == 2


def test_global_budget_wins_over_per_check():
    b = RequestBudget(2, per_check_cap=10)
    tok = _CHECK_NAME.set("check_x")
    try:
        assert b.take() and b.take()
        assert b.take() is False
        assert b.exhausted is True
    finally:
        _CHECK_NAME.reset(tok)


def test_take_n_counts_per_check():
    b = RequestBudget(100, per_check_cap=5)
    tok = _CHECK_NAME.set("check_n")
    try:
        assert b.take(3)
        assert b.take(3) is False
        assert b.take(2)
        assert b.per_check["check_n"] == 5
    finally:
        _CHECK_NAME.reset(tok)
