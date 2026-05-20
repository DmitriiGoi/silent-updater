from __future__ import annotations

import logging
from typing import Protocol

log = logging.getLogger(__name__)

SERVICE = "silent-updater"
GH_KEY = "github-models-token"
BB_KEY = "bitbucket-pat"


class TokenStore(Protocol):
    def save(self, key: str, value: str) -> None: ...
    def load(self, key: str) -> str | None: ...
    def delete(self, key: str) -> None: ...


class KeyringStore:
    def __init__(self, service: str = SERVICE):
        self.service = service

    def save(self, key: str, value: str) -> None:
        import keyring
        keyring.set_password(self.service, key, value)

    def load(self, key: str) -> str | None:
        import keyring
        try:
            return keyring.get_password(self.service, key)
        except Exception as ex:
            log.warning("keyring read failed for %s: %s", key, ex)
            return None

    def delete(self, key: str) -> None:
        import keyring
        try:
            keyring.delete_password(self.service, key)
        except Exception:
            pass


def default_store() -> TokenStore:
    return KeyringStore()
