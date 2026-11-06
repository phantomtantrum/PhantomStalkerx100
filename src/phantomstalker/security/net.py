"""Спільний HTTP-клієнт і простий файловий кеш для інструментів безпеки."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from phantomstalker import __version__

USER_AGENT = f"QuantPhantom/{__version__} (+https://github.com/phantomtantrum/PhantomStalkerx100)"


def client(**kwargs: Any) -> httpx.AsyncClient:
    headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
    return httpx.AsyncClient(timeout=kwargs.pop("timeout", 25.0), headers=headers,
                             follow_redirects=True, **kwargs)


def cache_dir() -> Path:
    base = os.environ.get("PHANTOMSTALKER_CACHE")
    path = Path(base).expanduser() if base else Path.home() / ".phantomstalker" / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_get(name: str, max_age: float) -> Any | None:
    file = cache_dir() / f"{name}.json"
    try:
        if time.time() - file.stat().st_mtime > max_age:
            return None
        return json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def cache_put(name: str, data: Any) -> None:
    try:
        (cache_dir() / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def describe_http_error(exc: Exception, service: str) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return f"{service}: доступ заборонено ({code}) — перевір ключ API (/keys)."
        if code == 429:
            return f"{service}: забагато запитів — зачекай хвилину й повтори."
        return f"{service} повернув помилку {code}."
    if isinstance(exc, httpx.TimeoutException):
        return f"{service} не відповідає (тайм-аут)."
    return f"Немає з'єднання з {service} — перевір мережу."
