"""Детерминированный профиль учебной цели по X-Scan-Seed."""
import main


def test_seeded_profile_deterministic():
    main._new_scan(seed=123)
    p1 = dict(main._state["profile"])
    main._new_scan(seed=123)
    p2 = dict(main._state["profile"])
    assert p1 == p2
    assert p1["seeded"] is True
    assert main._maybe(0.9) is True
    assert main._maybe(0.9) is True  # не зависит от порядка вызовов
    assert main._maybe(0.1) is False


def test_unseeded_profile_random():
    main._new_scan()
    assert main._state["profile"]["seeded"] is False
