"""Фейковий клієнт Anthropic, що імітує `client.beta.messages.stream(...)`."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any


class FakeStream:
    def __init__(self, chunks: list[str], stop_reason: str, delay: float = 0.0) -> None:
        self._chunks = chunks
        self._stop_reason = stop_reason
        self._delay = delay

    async def __aenter__(self) -> FakeStream:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    @property
    def text_stream(self):
        async def gen():
            for chunk in self._chunks:
                if self._delay:
                    await asyncio.sleep(self._delay)
                yield chunk

        return gen()

    async def get_final_message(self) -> Any:
        return SimpleNamespace(stop_reason=self._stop_reason, content=[])


class FakeClient:
    def __init__(self, chunks: list[str] | None = None, stop_reason: str = "end_turn",
                 error: Exception | None = None, delay: float = 0.0) -> None:
        self._delay = delay
        self.calls: list[dict[str, Any]] = []
        self._chunks = chunks if chunks is not None else ["Привіт", "! Як ти?"]
        self._stop_reason = stop_reason
        self._error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))
        self.available_models = ["claude-opus-5-5"]
        self.models = SimpleNamespace(retrieve=self._retrieve, list=self._list)

    async def _retrieve(self, model_id: str) -> Any:
        if model_id not in self.available_models:
            import anthropic
            import httpx2

            resp = httpx2.Response(404, request=httpx2.Request("GET", "https://api.anthropic.com/v1/models/x"))
            raise anthropic.NotFoundError(f"model: {model_id}", response=resp, body=None)
        return SimpleNamespace(id=model_id)

    def _list(self, **kwargs: Any):
        async def gen():
            for m in self.available_models:
                yield SimpleNamespace(id=m)

        return gen()

    def _stream(self, **kwargs: Any) -> FakeStream:
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return FakeStream(self._chunks, self._stop_reason, self._delay)
