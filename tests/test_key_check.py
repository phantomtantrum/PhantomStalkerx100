"""Перевірка ключа Anthropic і моделі — на справжньому SDK з підмінним HTTP."""

import anthropic
import httpx2
import pytest

from phantomstalker.services.copilot import CopilotError, CopilotService, pick_model


def service(handler, model="claude-opus-5-5"):
    def factory(key):
        return anthropic.AsyncAnthropic(api_key=key, max_retries=0,
                                        http_client=anthropic.DefaultAsyncHttpxClient(transport=httpx2.MockTransport(handler)))

    return CopilotService(api_key="sk-ant-test", model=model, client_factory=factory)


def err(status, kind, message):
    return httpx2.Response(status, json={"type": "error", "error": {"type": kind, "message": message}})


def models_handler(available):
    def handler(request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path.startswith("/v1/models/"):
            model = path.rsplit("/", 1)[-1]
            if model in available:
                return httpx2.Response(200, json={"id": model, "type": "model", "display_name": model,
                                                  "created_at": "2026-01-01T00:00:00Z"})
            return err(404, "not_found_error", f"model: {model}")
        if path == "/v1/models":
            return httpx2.Response(200, json={"data": [{"id": m, "type": "model", "display_name": m,
                                                        "created_at": "2026-01-01T00:00:00Z"} for m in available],
                                              "has_more": False, "first_id": None, "last_id": None})
        return err(404, "not_found_error", "nope")

    return handler


async def test_check_access_ok():
    check = await service(models_handler(["claude-opus-5-5"])).check_access()
    assert check.ok and "claude-opus-5-5" in check.message


async def test_check_access_bad_key():
    check = await service(lambda req: err(401, "authentication_error", "invalid x-api-key")).check_access()
    assert not check.ok and "401" in check.message and "sk-ant-api" in check.message


async def test_check_access_model_missing_suggests_available():
    check = await service(models_handler(["claude-haiku-4-5", "claude-sonnet-5-5"])).check_access()
    assert not check.ok and "404" in check.message
    assert check.suggestion == "claude-sonnet-5-5"  # найкраща з доступних за пріоритетом


async def test_stream_404_explains_cause(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://my-proxy.example/v1")
    svc = service(lambda req: err(404, "not_found_error", "model: claude-opus-5-5"))
    with pytest.raises(CopilotError) as info:
        async for _ in svc.chat([{"role": "user", "content": "hi"}]):
            pass
    text = str(info.value)
    assert "404" in text and "model: claude-opus-5-5" in text and "/key test" in text
    assert "ANTHROPIC_BASE_URL" in text and "my-proxy.example" in text


async def test_stream_other_errors_show_api_message():
    svc = service(lambda req: err(400, "invalid_request_error", "max_tokens: too large"))
    with pytest.raises(CopilotError, match="max_tokens: too large"):
        async for _ in svc.chat([{"role": "user", "content": "hi"}]):
            pass


def test_pick_model():
    assert pick_model(["claude-haiku-5-5", "claude-opus-5"]) == "claude-opus-5"
    assert pick_model(["some-new-model"]) == "some-new-model"
    assert pick_model([]) is None
