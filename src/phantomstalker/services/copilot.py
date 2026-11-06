"""Напарник-листування: полірує, змінює тон, перекладає й пропонує відповіді.

Працює лише з текстом, який користувач сам вставив або написав у застосунку.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

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
        f"You are {phantom_name}, the assistant inside QuantPhantom — a personal cybersecurity terminal "
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
            raise CopilotError("Ключ API не прийнято — задай інший через /key.") from exc
        except anthropic.PermissionDeniedError as exc:
            raise CopilotError("Доступ заборонено для цього ключа або моделі.") from exc
        except anthropic.RateLimitError as exc:
            raise CopilotError("Забагато запитів — зачекай трохи й спробуй ще раз.") from exc
        except anthropic.APIStatusError as exc:
            raise CopilotError(f"API повернуло помилку {exc.status_code}.") from exc
        except anthropic.APIConnectionError as exc:
            raise CopilotError("Немає з'єднання з API — перевір мережу.") from exc

        if final.stop_reason == "refusal":
            raise CopilotRefusal("Модель відмовилась виконувати цей запит.")
        if final.stop_reason == "max_tokens":
            yield "\n\n[…відповідь обрізано]"
