"""Подбор свободных портов в start.py: цель и сканер не должны столкнуться."""
import socket

import start


def test_free_port_returns_preferred_when_free():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert start._free_port(port) == port


def test_free_port_skips_occupied():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    busy = s.getsockname()[1]
    try:
        assert start._free_port(busy) != busy
    finally:
        s.close()


def test_pick_ports_avoids_collision(monkeypatch):
    table = {10000: 10001, 10001: 10001, 10002: 10002}
    monkeypatch.setattr(start, "_free_port", lambda pref: table[pref])
    api, web = start._pick_ports(10000, 10001)
    assert (api, web) == (10001, 10002)
    assert api != web


def test_pick_ports_normal_case(monkeypatch):
    monkeypatch.setattr(start, "_free_port", lambda pref: pref)
    assert start._pick_ports(8000, 8001) == (8000, 8001)
