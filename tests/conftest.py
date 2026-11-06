from __future__ import annotations

import pytest

from phantomstalker.storage.db import connect


class MemoryKeyring:
    """Замінник системного keyring для тестів."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.store.pop((service, username), None)


@pytest.fixture
def conn():
    connection = connect(":memory:")
    yield connection
    connection.close()


@pytest.fixture
def keyring_backend() -> MemoryKeyring:
    return MemoryKeyring()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    for name in ("ANTHROPIC_API_KEY", "HIBP_API_KEY", "ETHERSCAN_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PHANTOMSTALKER_CACHE", str(tmp_path / "cache"))


def mock_client(handler):
    """httpx.AsyncClient, що відповідає функцією handler(request) -> httpx.Response."""
    import httpx

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def fake(prefix: str, n: int, alphabet: str = "Ab3Xk9Qz") -> str:
    """Фіктивний токен, зібраний під час виконання (щоб у коді не було «справжніх» рядків)."""
    return prefix + (alphabet * (n // len(alphabet) + 1))[:n]
