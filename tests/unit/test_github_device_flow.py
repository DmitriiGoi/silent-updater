from __future__ import annotations

import httpx
import pytest

from silent_updater.auth import github_device_flow
from silent_updater.auth.github_device_flow import (
    DEVICE_CODE_URL,
    TOKEN_URL,
    DeviceCodeResponse,
    DeviceFlowError,
    poll_for_token,
    request_device_code,
)


def test_request_device_code(httpx_mock):  # noqa: ANN001 — pytest-httpx fixture
    httpx_mock.add_response(
        url=DEVICE_CODE_URL,
        json={
            "device_code": "DCODE",
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        },
    )
    with httpx.Client() as c:
        resp = request_device_code("client123", client=c)
    assert resp.device_code == "DCODE"
    assert resp.user_code == "ABCD-1234"
    assert resp.interval == 5


def test_poll_authorization_pending_then_success(httpx_mock):  # noqa: ANN001
    httpx_mock.add_response(url=TOKEN_URL, json={"error": "authorization_pending"})
    httpx_mock.add_response(url=TOKEN_URL, json={"access_token": "gho_secret", "token_type": "bearer"})

    sleeps: list[float] = []
    times = [0.0]
    def fake_now(): return times[0]
    def fake_sleep(s):
        sleeps.append(s)
        times[0] += s

    device = DeviceCodeResponse("DCODE", "ABCD", "https://github.com/login/device", 60, 1)
    with httpx.Client() as c:
        token = poll_for_token("client123", device, client=c, now=fake_now, sleep=fake_sleep)
    assert token == "gho_secret"
    assert sleeps == [1, 1]


def test_poll_slow_down_increases_interval(httpx_mock):  # noqa: ANN001
    httpx_mock.add_response(url=TOKEN_URL, json={"error": "slow_down"})
    httpx_mock.add_response(url=TOKEN_URL, json={"access_token": "tok"})

    sleeps: list[float] = []
    times = [0.0]
    def fake_now(): return times[0]
    def fake_sleep(s):
        sleeps.append(s)
        times[0] += s

    device = DeviceCodeResponse("DCODE", "ABCD", "url", 60, 1)
    with httpx.Client() as c:
        token = poll_for_token("client123", device, client=c, now=fake_now, sleep=fake_sleep)
    assert token == "tok"
    assert sleeps == [1, 6]


def test_poll_expired_token_raises(httpx_mock):  # noqa: ANN001
    httpx_mock.add_response(url=TOKEN_URL, json={"error": "expired_token"})
    device = DeviceCodeResponse("DCODE", "ABCD", "url", 60, 1)
    times = [0.0]
    def fake_now(): return times[0]
    def fake_sleep(s): times[0] += s
    with httpx.Client() as c:
        with pytest.raises(DeviceFlowError, match="expired_token"):
            poll_for_token("client123", device, client=c, now=fake_now, sleep=fake_sleep)


def test_poll_deadline_exceeded(httpx_mock):  # noqa: ANN001 — no responses queued
    device = DeviceCodeResponse("DCODE", "ABCD", "url", 5, 10)
    times = [0.0]
    def fake_now(): return times[0]
    def fake_sleep(s): times[0] += s
    with httpx.Client() as c:
        with pytest.raises(DeviceFlowError, match="expired"):
            poll_for_token("client123", device, client=c, now=fake_now, sleep=fake_sleep)
