"""Юнит-тесты anti-DNS-rebinding пиннинга."""
import httpx
from scanner.security import _pin_request, resolve_target_ip, pinned_client_kwargs


def test_pin_request_preserves_host_and_sni():
    req = httpx.Request("GET", "https://example.com/path?q=1")
    pinned = _pin_request(req, "example.com", "93.184.216.34")
    assert pinned.url.host == "93.184.216.34"
    assert pinned.url.path == "/path"
    assert pinned.headers["host"] == "example.com"
    assert pinned.extensions["sni_hostname"] == "example.com"


def test_resolve_ip_literal():
    assert resolve_target_ip("127.0.0.1") == "127.0.0.1"


def test_pinned_kwargs_for_ip_target_empty():
    assert pinned_client_kwargs("http://127.0.0.1:8000") == {}
