from __future__ import annotations

import time
import webbrowser
from dataclasses import dataclass

import httpx

from silent_updater.auth.token_store import GH_KEY, TokenStore, default_store


DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"

DEFAULT_SCOPE = "read:user"


class DeviceFlowError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceCodeResponse:
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


def request_device_code(client_id: str, scope: str = DEFAULT_SCOPE,
                        client: httpx.Client | None = None) -> DeviceCodeResponse:
    owns = client is None
    if client is None:
        client = httpx.Client(timeout=30.0)
    try:
        resp = client.post(
            DEVICE_CODE_URL,
            data={"client_id": client_id, "scope": scope},
            headers={"Accept": "application/json"},
        )
    finally:
        if owns:
            client.close()
    if resp.status_code != 200:
        raise DeviceFlowError(
            f"device-code request failed: {resp.status_code} {resp.text}"
        )
    j = resp.json()
    return DeviceCodeResponse(
        device_code=j["device_code"],
        user_code=j["user_code"],
        verification_uri=j["verification_uri"],
        expires_in=int(j["expires_in"]),
        interval=int(j["interval"]),
    )


def poll_for_token(
    client_id: str,
    device: DeviceCodeResponse,
    *,
    client: httpx.Client | None = None,
    now=time.time,
    sleep=time.sleep,
) -> str:
    """Poll token endpoint until success/expiry. Returns access_token."""
    interval = device.interval
    deadline = now() + device.expires_in
    owns = client is None
    if client is None:
        client = httpx.Client(timeout=30.0)
    try:
        while now() < deadline:
            sleep(interval)
            if now() >= deadline:
                break
            resp = client.post(
                TOKEN_URL,
                data={
                    "client_id": client_id,
                    "device_code": device.device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json"},
            )
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if "access_token" in data:
                return data["access_token"]
            error = data.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            if error in {"expired_token", "access_denied", "unsupported_grant_type",
                         "incorrect_client_credentials", "incorrect_device_code"}:
                raise DeviceFlowError(f"device flow failed: {error}: {data.get('error_description', '')}")
            # unknown — fail loud
            raise DeviceFlowError(f"unexpected token response: {resp.status_code} {resp.text}")
    finally:
        if owns:
            client.close()
    raise DeviceFlowError("device code expired before user completed authorization")


def login(client_id: str, scope: str = DEFAULT_SCOPE,
          store: TokenStore | None = None, open_browser: bool = True) -> str:
    """Interactive: print code, open browser, poll. Save token. Return token."""
    store = store or default_store()
    device = request_device_code(client_id=client_id, scope=scope)
    print(f"\nOpen {device.verification_uri} and enter code: {device.user_code}")
    print(f"(this code expires in {device.expires_in}s)\n")
    if open_browser:
        try:
            webbrowser.open(device.verification_uri)
        except Exception:
            pass
    token = poll_for_token(client_id, device)
    store.save(GH_KEY, token)
    return token


def get_or_login(client_id: str, scope: str = DEFAULT_SCOPE,
                 store: TokenStore | None = None) -> str:
    store = store or default_store()
    existing = store.load(GH_KEY)
    if existing:
        return existing
    return login(client_id=client_id, scope=scope, store=store)


def logout(store: TokenStore | None = None) -> None:
    store = store or default_store()
    store.delete(GH_KEY)
