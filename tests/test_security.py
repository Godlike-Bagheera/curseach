"""Юнит-тесты security.py: SSRF, сессии, rate-limit, имена файлов."""

import time

import pytest
from fastapi import HTTPException

from scanner import security


def test_validate_target_url_basic():
    assert security.validate_target_url("") is not None
    assert security.validate_target_url(None) is not None
    assert security.validate_target_url("ftp://x") is not None
    assert security.validate_target_url("http://") is not None
    assert security.validate_target_url("http://exa mple.com") is not None
    assert security.validate_target_url("http://127.0.0.1:8000") is None
    assert security.validate_target_url("http://localhost:8000") is None


def test_validate_target_url_no_dot_host():
    assert security.validate_target_url("http://somehost") is not None


def test_ssrf_metadata_always_blocked():
    assert security.ssrf_check_host("169.254.169.254") is not None
    assert security.validate_target_url("http://169.254.169.254/latest/") is not None


def test_ssrf_private_blocked_when_flag_off(monkeypatch):
    monkeypatch.setattr(security, "SSRF_ALLOW_PRIVATE", False)
    assert security.ssrf_check_host("127.0.0.1") is not None
    assert security.ssrf_check_host("10.0.0.1") is not None
    assert security.ssrf_check_host("192.168.1.1") is not None


def test_ssrf_private_allowed_when_flag_on(monkeypatch):
    monkeypatch.setattr(security, "SSRF_ALLOW_PRIVATE", True)
    assert security.ssrf_check_host("127.0.0.1") is None
    assert security.ssrf_check_host("10.0.0.1") is None


def test_is_blocked_ip_invalid():
    assert security._is_blocked_ip("not-an-ip") is False


def test_ssrf_decimal_obfuscation(monkeypatch):
    monkeypatch.setattr(security, "SSRF_ALLOW_PRIVATE", False)
    assert security.ssrf_check_host("2130706433") is not None


def test_safe_host_for_filename():
    assert security.safe_host_for_filename("http://Example.com:8000/x") == "Example.com-8000"
    assert security.safe_host_for_filename("???") == "target"


def test_sessions_lifecycle():
    sid = security.create_session("admin")
    assert security.get_current_user(sid) == "admin"
    security.destroy_session(sid)
    assert security.get_current_user(sid) is None


def test_require_admin_and_user():
    sid = security.create_session("admin")
    assert security.require_admin(sid) == "admin"
    guest = security.create_session("guest")
    with pytest.raises(HTTPException):
        security.require_admin(guest)
    with pytest.raises(HTTPException):
        security.require_user(None)
    security.destroy_session(sid)
    security.destroy_session(guest)


def test_session_ttl_expiry(monkeypatch):
    sid = security.create_session("admin")
    real = time.time()
    monkeypatch.setattr(security.time, "time", lambda: real + security.SESSION_TTL_SECONDS + 10)
    assert security.get_current_user(sid) is None


def test_login_rate_limit():
    security._login_attempts.clear()
    ip = "1.2.3.4"
    for _ in range(security.LOGIN_MAX_ATTEMPTS):
        assert security.check_login_rate(ip) is True
    assert security.check_login_rate(ip) is False
    security._login_attempts.clear()


def test_resolve_target_ip_literal():
    assert security.resolve_target_ip("127.0.0.1") == "127.0.0.1"
    assert security.resolve_target_ip("nonexistent.invalid") is None


def test_pinned_client_kwargs_disabled(monkeypatch):
    monkeypatch.setattr(security, "SCAN_PIN_DNS", False)
    assert security.pinned_client_kwargs("http://example.com") == {}
