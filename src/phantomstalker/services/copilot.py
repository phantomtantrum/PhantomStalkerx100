"""Напарник-листування: полірує, змінює тон, перекладає й пропонує відповіді.

Працює лише з текстом, який користувач сам вставив або написав у застосунку.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import os

import anthropic

DEFAULT_MODEL = "claude-opus-5-5"
# Серверний fallback: якщо модель відхилить запит, API саме перезапустить його
# на відповідній моделі в межах того ж виклику.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000


class Action(StrEnum):
    POLISH = "polish"
    WARMER = "warmer"
    FORMAL = "formal"
    SHORTER = "shorter"
    TRANSLATE = "translate"
    REPLY = "reply"


_INSTRUCTIONS: dict[Action, str] = {
    Action.POLISH: (
        "Polish this draft: fix grammar, spelling and flow, keep the meaning, "
        "length and the author's voice."
    ),
    Action.WARMER: "Rewrite this draft so it sounds warmer and friendlier, keeping the meaning.",
    Action.FORMAL: "Rewrite this draft in a more formal, professional register, keeping the meaning.",
    Action.SHORTER: "Make this draft noticeably shorter and punchier without losing key points.",
    Action.TRANSLATE: "Translate this draft into {language}, keeping the author's tone and voice.",
    Action.REPLY: (
        "The text below is a message the author received. Draft a reply the author could send, "
        "in the author's voice and in the same language as the received message."
    ),
}


@dataclass(frozen=True)
class CopilotRequest:
    action: Action
    text: str
    target_language: str = ""
    context: str = ""  # необов'язкові нотатки користувача (напр. про адресата)


class CopilotError(Exception):
    """Помилка з повідомленням, яке можна показати користувачу."""


class CopilotRefusal(CopilotError):
    pass


def build_system_prompt(phantom_name: str, tone_profile: str) -> str:
    return (
        f"You are {phantom_name}, a small, friendly pixel ghost with a curly tail who lives in the user's terminal "
        "and acts as their personal writing co-pilot inside the PhantomStalker app.\n\n"
        "Your job is to help the user write *their own* messages in *their own* voice. "
        "The user pastes a draft or a message they received and picks an action.\n\n"
        f"The user's voice and tone profile: {tone_profile or 'natural and friendly'}.\n\n"
        "Rules:\n"
        "- Output only the resulting message text, ready to copy and send: no preamble, "
        "no surrounding quotes, no explanations or alternatives.\n"
        "- Keep the original language unless the action asks for a translation.\n"
        "- Do not invent facts, promises, names or details that are not in the draft or context.\n"
        "- Keep any names, links, numbers and emoji from the original.\n"
        "- You help one person with their own correspondence. Do not produce bulk or spam "
        "messages, and do not write messages meant to impersonate someone else."
    )


def build_user_prompt(request: CopilotRequest, default_language: str = "English") -> str:
    language = request.target_language.strip() or default_language
    instruction = _INSTRUCTIONS[request.action].format(language=language)
    parts = [instruction]
    if request.context.strip():
        parts.append(f"<context>\n{request.context.strip()}\n</context>")
    parts.append(f"<text>\n{request.text.strip()}\n</text>")
    return "\n\n".join(parts)


ClientFactory = Callable[[str | None], Any]


def _default_client_factory(api_key: str | None) -> anthropic.AsyncAnthropic:
    return anthropic.AsyncAnthropic(api_key=api_key) if api_key else anthropic.AsyncAnthropic()


def build_chat_system_prompt(phantom_name: str, tone_profile: str, language: str) -> str:
    return (
        f"You are {phantom_name}, the assistant inside PhantomStalker — a personal cybersecurity terminal "
        "with a social co-pilot. You are a calm, precise security analyst and a friendly helper.\n\n"
        "Security work: the app runs local tools (system audit, SSH audit, auth-log analysis, secret scanning, "
        "dependency CVEs, phishing analysis, file checks, password and breach checks, wallet approvals, "
        "encryption, photo metadata, threat digests) and may paste their reports to you. Explain findings in "
        "plain language, rank them by real-world risk, and give concrete, copy-pasteable fix steps for the "
        "user's own systems. Don't exaggerate; say clearly when something is fine. Help only with defending "
        "the user's own systems, accounts and code: no attacking, scanning or accessing systems they don't own, "
        "no malware, no bypassing others' security. Never ask for passwords, seed phrases or private keys; "
        "if the user shares one, tell them to treat it as compromised.\n\n"
        "Social work: help the user write their own messages and prepare for conversations; match their voice: "
        f"{tone_profile or 'natural'}. Use only what the user shares about people; no looking people up.\n\n"
        f"Reply in the user's language (default: {language or 'Ukrainian'}). Replies appear in a terminal: "
        "short paragraphs and simple lists, commands in `backticks`, no headings or tables."
    )


# Порядок, у якому пропонуємо модель, якщо поточна недоступна для ключа.
PREFERRED_MODELS = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-opus-5", "claude-sonnet-5",
                    "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-5-5", "claude-haiku-4-5")


def _api_detail(exc: anthropic.APIStatusError) -> str:
    """Текст помилки від API (без службових обгорток)."""
    body = exc.body if isinstance(exc.body, dict) else {}
    err = body.get("error") if isinstance(body.get("error"), dict) else body
    message = (err or {}).get("message") or getattr(exc, "message", "") or ""
    return str(message).strip()[:200]


def base_url_note() -> str:
    url = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if url and "api.anthropic.com" not in url:
        return (f" Увага: задано змінну ANTHROPIC_BASE_URL={url} — запити йдуть туди, а не на api.anthropic.com. "
                "Прибери її, якщо це не навмисно.")
    return ""


def pick_model(available: list[str]) -> str | None:
    for model in PREFERRED_MODELS:
        if model in available:
            return model
    return available[0] if available else None


@dataclass
class AccessCheck:
    ok: bool
    message: str
    suggestion: str | None = None  # модель, яку варто ввімкнути


class CopilotService:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        phantom_name: str = "Phantom",
        tone_profile: str = "",
        default_language: str = "English",
        client_factory: ClientFactory = _default_client_factory,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.phantom_name = phantom_name
        self.tone_profile = tone_profile
        self.default_language = default_language
        self._client_factory = client_factory
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self._client_factory(self.api_key)
        return self._client

    async def check_access(self) -> AccessCheck:
        """Перевіряє ключ і модель безкоштовним запитом до Models API; підбирає доступну модель."""
        if not self.api_key:
            return AccessCheck(False, "Ключ Anthropic не задано — додай його: /key")
        client = self._get_client()
        try:
            await client.models.retrieve(self.model)
            return AccessCheck(True, f"Ключ працює, модель {self.model} доступна")
        except anthropic.AuthenticationError:
            return AccessCheck(False, "Ключ не прийнято (401): він недійсний, відкликаний або скопійований не повністю. "
                                      "Ключ API має починатися з sk-ant-api…" + base_url_note())
        except anthropic.PermissionDeniedError as exc:
            return AccessCheck(False, f"Доступ заборонено (403): {_api_detail(exc)}")
        except anthropic.NotFoundError:
            pass
        except anthropic.APIStatusError as exc:
            return AccessCheck(False, f"API повернуло помилку {exc.status_code}: {_api_detail(exc)}" + base_url_note())
        except anthropic.APIConnectionError:
            return AccessCheck(False, "Немає з'єднання з API — перевір мережу." + base_url_note())
        # модель не знайдена — дивимось, які доступні
        try:
            available = [m.id async for m in client.models.list(limit=100)]
        except anthropic.APIError:
            available = []
        best = pick_model(available)
        msg = f"Ключ працює, але модель {self.model} недоступна для нього (404)."
        if best:
            msg += f" Доступна, наприклад: {best}."
        return AccessCheck(False, msg + base_url_note(), best)

    async def stream(self, request: CopilotRequest) -> AsyncIterator[str]:
        """Дія над текстом (полірування, тон, переклад…): стрімить готове повідомлення."""
        if not request.text.strip():
            raise CopilotError("Порожній текст — нічого покращувати.")
        system = build_system_prompt(self.phantom_name, self.tone_profile)
        messages = [{"role": "user", "content": build_user_prompt(request, self.default_language)}]
        async for chunk in self._stream(system, messages):
            yield chunk

    async def chat(self, messages: list[dict[str, Any]]) -> AsyncIterator[str]:
        """Вільна розмова з фантомом; `messages` — уся історія сесії."""
        system = build_chat_system_prompt(self.phantom_name, self.tone_profile, self.default_language)
        async for chunk in self._stream(system, messages):
            yield chunk

    async def _stream(self, system: str, messages: list[dict[str, Any]]) -> AsyncIterator[str]:
        try:
            client = self._get_client()
            async with client.beta.messages.stream(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=messages,
                # Листування й розмова — легкі завдання: низьке зусилля = швидше й дешевше.
                output_config={"effort": "low"},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            ) as stream:
                async for text in stream.text_stream:
                    yield text
                final = await stream.get_final_message()
        except anthropic.AuthenticationError as exc:
            raise CopilotError("Ключ API не прийнято (401) — перевір його: /key test, або задай інший: /key."
                               + base_url_note()) from exc
        except anthropic.PermissionDeniedError as exc:
            raise CopilotError(f"Доступ заборонено (403): {_api_detail(exc) or 'ключ не має доступу до моделі'}. "
                               "Перевір: /key test") from exc
        except anthropic.NotFoundError as exc:
            raise CopilotError(f"Не знайдено (404): {_api_detail(exc) or self.model}. Схоже, модель {self.model} "
                               "недоступна для цього ключа — /key test підкаже доступну модель." + base_url_note()) from exc
        except anthropic.RateLimitError as exc:
            raise CopilotError("Забагато запитів — зачекай трохи й спробуй ще раз.") from exc
        except anthropic.APIStatusError as exc:
            detail = _api_detail(exc)
            raise CopilotError(f"API повернуло помилку {exc.status_code}" + (f": {detail}" if detail else ".")
                               + base_url_note()) from exc
        except anthropic.APIConnectionError as exc:
            raise CopilotError("Немає з'єднання з API — перевір мережу.") from exc

        if final.stop_reason == "refusal":
            raise CopilotRefusal("Модель відмовилась виконувати цей запит.")
        if final.stop_reason == "max_tokens":
            yield "\n\n[…відповідь обрізано]"
