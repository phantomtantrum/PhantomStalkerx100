"""Налаштування: звичайні значення — в SQLite, ключ API — тільки в keyring."""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Protocol

KEYRING_SERVICE = "phantomstalker"
KEYRING_API_KEY = "anthropic_api_key"

# назва → (ім'я в keyring, змінна середовища, опис, де взяти)
SECRETS: dict[str, tuple[str, str, str, str]] = {
    "anthropic": (KEYRING_API_KEY, "ANTHROPIC_API_KEY", "Anthropic API (розмова й /explain)",
                  "platform.claude.com"),
    "hibp": ("hibp_api_key", "HIBP_API_KEY", "Have I Been Pwned (/breach)", "haveibeenpwned.com/API/Key"),
    "etherscan": ("etherscan_api_key", "ETHERSCAN_API_KEY", "Etherscan (/approvals)", "etherscan.io/apis"),
    "abusech": ("abusech_auth_key", "ABUSECH_AUTH_KEY", "abuse.ch / MalwareBazaar (/file)", "auth.abuse.ch"),
}

DEFAULTS: dict[str, str] = {
    "phantom_name": "Phantom",
    "tone_profile": "дружній, лаконічний, без канцеляризмів, з легким гумором",
    "default_language": "українська",
    "model": "claude-opus-5-5",
    "stale_after_days": "30",
    "color": "mono",
    "stack": "",
}


class KeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...
    def set_password(self, service: str, username: str, password: str) -> None: ...
    def delete_password(self, service: str, username: str) -> None: ...


def _system_keyring() -> Any:
    import keyring

    return keyring


class SettingsService:
    def __init__(self, conn: sqlite3.Connection, keyring_backend: KeyringBackend | None = None) -> None:
        self.conn = conn
        self._keyring = keyring_backend if keyring_backend is not None else _system_keyring()

    # --- звичайні налаштування --------------------------------------------
    def get(self, key: str, default: str | None = None) -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is not None:
            return row["value"]
        if default is not None:
            return default
        return DEFAULTS.get(key, "")

    def set(self, key: str, value: str) -> None:
        if key in {v[0] for v in SECRETS.values()}:
            raise ValueError("Ключі API зберігаються лише в keyring — використовуй set_secret()")
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    @property
    def phantom_name(self) -> str:
        return self.get("phantom_name").strip() or DEFAULTS["phantom_name"]

    @property
    def tone_profile(self) -> str:
        return self.get("tone_profile")

    @property
    def model(self) -> str:
        return self.get("model").strip() or DEFAULTS["model"]

    @property
    def stale_after_days(self) -> int:
        try:
            return max(1, int(self.get("stale_after_days")))
        except ValueError:
            return int(DEFAULTS["stale_after_days"])

    # --- секрети (тільки keyring або змінні середовища) ------------------------------------
    def get_secret(self, name: str) -> str | None:
        keyring_name, env_name, *_ = SECRETS[name]
        try:
            stored = self._keyring.get_password(KEYRING_SERVICE, keyring_name)
        except Exception:  # немає бекенду keyring (напр. headless-сервер)
            stored = None
        return stored or os.environ.get(env_name) or None

    def set_secret(self, name: str, value: str) -> None:
        value = value.strip()
        if value:
            self._keyring.set_password(KEYRING_SERVICE, SECRETS[name][0], value)
        else:
            self.clear_secret(name)

    def clear_secret(self, name: str) -> None:
        try:
            self._keyring.delete_password(KEYRING_SERVICE, SECRETS[name][0])
        except Exception:
            pass

    def has_secret(self, name: str) -> bool:
        return bool(self.get_secret(name))

    # сумісність зі старим API
    def get_api_key(self) -> str | None:
        return self.get_secret("anthropic")

    def set_api_key(self, value: str) -> None:
        self.set_secret("anthropic", value)

    def clear_api_key(self) -> None:
        self.clear_secret("anthropic")

    def has_api_key(self) -> bool:
        return self.has_secret("anthropic")

    @property
    def stack(self) -> list[str]:
        return [t.strip() for t in self.get("stack").split(",") if t.strip()]


def load_dotenv(path: str | Path = ".env") -> None:
    """Мінімальний читач .env (KEY=VALUE). Не перезаписує вже задані змінні."""
    file = Path(path)
    if not file.is_file():
        return
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if value[:1] in ('"', "'") and value[1:].find(value[0]) >= 0:
            value = value[1:1 + value[1:].find(value[0])]  # у лапках «#» — частина значення
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()  # коментар у кінці рядка
            if value.startswith("#"):
                value = ""
        if key and value:
            os.environ.setdefault(key, value)
